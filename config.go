package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// anyUsernameRegex matches every downstream username. sshpiper rewrites the
// upstream username with regexp.ReplaceAllString, so the pattern must be
// anchored: an unanchored ".*" also matches the empty string at end-of-input
// and would emit the replacement twice.
const anyUsernameRegex = `^.*$`

// Config is the fully validated, decoded runtime configuration.
type Config struct {
	ListenPort     int
	UpstreamAddr   string // host:port, IPv6 bracketed
	UpstreamUser   string
	AuthorizedKeys []byte // OpenSSH authorized_keys content
	UpstreamKey    []byte // PEM private key used towards the upstream
	KnownHosts     []byte // OpenSSH known_hosts content
	HostKey        []byte // PEM private key presented to clients
	// HostKeyGenerated reports that HostKey was created at startup because
	// SSH_SERVER_HOST_KEY_B64 was unset.
	HostKeyGenerated bool
}

// Fingerprints of the validated key material, for startup logging.
type Fingerprints struct {
	AuthorizedKeys []string
	UpstreamKey    string
	HostKey        string
}

// LoadConfig reads every setting from getenv, decodes the Base64 blobs and
// validates all key material. All problems are reported at once.
func LoadConfig(getenv func(string) string) (*Config, *Fingerprints, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	cfg := &Config{}
	fp := &Fingerprints{}

	host := strings.TrimSpace(getenv("SSH_UPSTREAM_HOST"))
	switch {
	case host == "":
		fail("SSH_UPSTREAM_HOST is required")
	case strings.ContainsFunc(host, illegalHostRune):
		fail("SSH_UPSTREAM_HOST %q contains an illegal character", host)
	}

	upstreamPort, err := envPort(getenv, "SSH_UPSTREAM_PORT", 22)
	if err != nil {
		errs = append(errs, err)
	}
	if host != "" && upstreamPort != 0 {
		cfg.UpstreamAddr = net.JoinHostPort(host, strconv.Itoa(upstreamPort))
	}

	cfg.UpstreamUser = getenv("SSH_UPSTREAM_USER")
	switch {
	case cfg.UpstreamUser == "":
		fail("SSH_UPSTREAM_USER is required")
	case strings.ContainsFunc(cfg.UpstreamUser, unicode.IsSpace):
		fail("SSH_UPSTREAM_USER %q contains whitespace", cfg.UpstreamUser)
	}

	cfg.ListenPort, err = envPort(getenv, "SSH_LISTEN_PORT", 2222)
	if err != nil {
		errs = append(errs, err)
	}

	if raw, err := decodeBase64Env(getenv, "SSH_AUTHORIZED_KEY_B64", true); err != nil {
		errs = append(errs, err)
	} else if cfg.AuthorizedKeys, fp.AuthorizedKeys, err = validateAuthorizedKeys(raw); err != nil {
		fail("SSH_AUTHORIZED_KEY_B64: %w", err)
	}

	if raw, err := decodeBase64Env(getenv, "SSH_UPSTREAM_PRIVATE_KEY_B64", true); err != nil {
		errs = append(errs, err)
	} else if fp.UpstreamKey, err = privateKeyFingerprint(raw); err != nil {
		fail("SSH_UPSTREAM_PRIVATE_KEY_B64: %w", err)
	} else {
		cfg.UpstreamKey = raw
	}

	if raw, err := decodeBase64Env(getenv, "SSH_UPSTREAM_KNOWN_HOSTS_B64", true); err != nil {
		errs = append(errs, err)
	} else if cfg.UpstreamAddr == "" {
		// Nothing to match against; the address error is already reported.
	} else if err := ValidateKnownHosts(raw, cfg.UpstreamAddr); err != nil {
		fail("SSH_UPSTREAM_KNOWN_HOSTS_B64: %w", err)
	} else {
		cfg.KnownHosts = raw
	}

	switch raw, err := decodeBase64Env(getenv, "SSH_SERVER_HOST_KEY_B64", false); {
	case err != nil:
		errs = append(errs, err)
	case raw == nil:
		key, fingerprint, err := generateHostKey()
		if err != nil {
			fail("generate host key: %w", err)
		}
		cfg.HostKey, cfg.HostKeyGenerated, fp.HostKey = key, true, fingerprint
	default:
		if fp.HostKey, err = privateKeyFingerprint(raw); err != nil {
			fail("SSH_SERVER_HOST_KEY_B64: %w", err)
		} else {
			cfg.HostKey = raw
		}
	}

	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}
	return cfg, fp, nil
}

func envPort(getenv func(string) string, name string, def int) (int, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return def, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be an integer in 1-65535, got %q", name, raw)
	}
	return port, nil
}

// decodeBase64Env decodes a Base64 environment value, tolerating the embedded
// newlines that shells and secret stores commonly introduce. A missing
// optional value yields (nil, nil).
func decodeBase64Env(getenv func(string) string, name string, required bool) ([]byte, error) {
	raw := strings.Join(strings.Fields(getenv(name)), "")
	if raw == "" {
		if required {
			return nil, fmt.Errorf("%s is required", name)
		}
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Tolerate unpadded Base64.
		if data, err = base64.RawStdEncoding.DecodeString(raw); err != nil {
			return nil, fmt.Errorf("%s is not valid Base64: %w", name, err)
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s decodes to an empty value", name)
	}
	return data, nil
}

// validateAuthorizedKeys parses every non-comment line and returns the
// normalized file content plus one SHA256 fingerprint per key.
func validateAuthorizedKeys(data []byte) ([]byte, []string, error) {
	var kept []string
	var fingerprints []string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		// sshpiper matches certificates against trusted_user_ca_keys, never
		// against authorized_keys, so a certificate here could never
		// authenticate anybody.
		if _, isCert := key.(*ssh.Certificate); isCert {
			return nil, nil, fmt.Errorf("line %d: user certificates are not supported, use a plain public key", i+1)
		}
		kept = append(kept, line)
		fingerprints = append(fingerprints, ssh.FingerprintSHA256(key))
	}
	if len(kept) == 0 {
		return nil, nil, errors.New("contains no public key")
	}
	return []byte(strings.Join(kept, "\n") + "\n"), fingerprints, nil
}

// hostCharset is everything a hostname or IP literal may contain. sshpiper
// turns the upstream address into a "tcp://host:port" URL, so URI delimiters
// such as '?', '#', '/' and '%' must never reach it.
const hostCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:"

func illegalHostRune(r rune) bool { return !strings.ContainsRune(hostCharset, r) }

func privateKeyFingerprint(pemBytes []byte) (string, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return "", errors.New("passphrase-protected private keys are not supported")
		}
		return "", err
	}
	return ssh.FingerprintSHA256(signer.PublicKey()), nil
}

func generateHostKey() ([]byte, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(block), ssh.FingerprintSHA256(sshPub), nil
}

// Mirrors of the sshpiper yaml plugin config structs
// (plugin/yaml/yaml.go @ v1.6.1). The `_data` fields are standard Base64.
type piperConfig struct {
	Version string      `yaml:"version"`
	Pipes   []piperPipe `yaml:"pipes"`
}

type piperPipe struct {
	From []piperFrom `yaml:"from"`
	To   piperTo     `yaml:"to"`
}

type piperFrom struct {
	Username           string `yaml:"username"`
	UsernameRegexMatch bool   `yaml:"username_regex_match"`
	AuthorizedKeysData string `yaml:"authorized_keys_data"`
}

type piperTo struct {
	Username       string `yaml:"username"`
	Host           string `yaml:"host"`
	PrivateKeyData string `yaml:"private_key_data"`
	KnownHostsData string `yaml:"known_hosts_data"`
}

// RenderPipeConfig builds the sshpiper yaml plugin document. Key material is
// inlined as Base64 so that no separate secret file is written.
func (c *Config) RenderPipeConfig() ([]byte, error) {
	return yaml.Marshal(piperConfig{
		Version: "1.0",
		Pipes: []piperPipe{{
			From: []piperFrom{{
				Username:           anyUsernameRegex,
				UsernameRegexMatch: true,
				AuthorizedKeysData: base64.StdEncoding.EncodeToString(c.AuthorizedKeys),
			}},
			To: piperTo{
				Username:       escapeRegexpTemplate(c.UpstreamUser),
				Host:           c.UpstreamAddr,
				PrivateKeyData: base64.StdEncoding.EncodeToString(c.UpstreamKey),
				KnownHostsData: base64.StdEncoding.EncodeToString(c.KnownHosts),
			},
		}},
	})
}

// escapeRegexpTemplate protects the upstream username from being treated as a
// regexp expansion template by sshpiper's regexp.ReplaceAllString call.
func escapeRegexpTemplate(s string) string {
	return strings.ReplaceAll(s, "$", "$$")
}
