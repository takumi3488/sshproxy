package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// testKey returns a fresh ed25519 key as (PEM private key, authorized_keys
// line, known_hosts public key field).
func testKey(t *testing.T) (privPEM []byte, authorizedKey []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), ssh.MarshalAuthorizedKey(sshPub)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// validEnv returns a complete, working environment plus the raw material it
// was built from.
func validEnv(t *testing.T) map[string]string {
	t.Helper()
	_, clientPub := testKey(t)
	upstreamPriv, _ := testKey(t)
	_, hostPub := testKey(t)
	return map[string]string{
		"SSH_AUTHORIZED_KEY_B64":       b64(clientPub),
		"SSH_UPSTREAM_PRIVATE_KEY_B64": b64(upstreamPriv),
		"SSH_UPSTREAM_HOST":            "upstream.example",
		"SSH_UPSTREAM_USER":            "deploy",
		"SSH_UPSTREAM_KNOWN_HOSTS_B64": b64([]byte("upstream.example " + string(hostPub))),
	}
}

func getenvFrom(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	env := validEnv(t)
	cfg, fp, err := LoadConfig(getenvFrom(env))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenPort != 2222 {
		t.Errorf("ListenPort = %d, want 2222", cfg.ListenPort)
	}
	if cfg.UpstreamAddr != "upstream.example:22" {
		t.Errorf("UpstreamAddr = %q, want upstream.example:22", cfg.UpstreamAddr)
	}
	if !cfg.HostKeyGenerated {
		t.Error("HostKeyGenerated = false, want true when SSH_SERVER_HOST_KEY_B64 is unset")
	}
	if _, err := ssh.ParsePrivateKey(cfg.HostKey); err != nil {
		t.Errorf("generated host key is unusable: %v", err)
	}
	if len(fp.AuthorizedKeys) != 1 || !strings.HasPrefix(fp.AuthorizedKeys[0], "SHA256:") {
		t.Errorf("AuthorizedKeys fingerprints = %v", fp.AuthorizedKeys)
	}
}

func TestLoadConfigExplicitPortsAndHostKey(t *testing.T) {
	env := validEnv(t)
	hostKey, _ := testKey(t)
	_, upstreamHostPub := testKey(t)
	env["SSH_LISTEN_PORT"] = "2022"
	env["SSH_UPSTREAM_PORT"] = "2200"
	env["SSH_SERVER_HOST_KEY_B64"] = b64(hostKey)
	env["SSH_UPSTREAM_KNOWN_HOSTS_B64"] = b64([]byte("[upstream.example]:2200 " + string(upstreamHostPub)))

	cfg, _, err := LoadConfig(getenvFrom(env))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenPort != 2022 || cfg.UpstreamAddr != "upstream.example:2200" {
		t.Errorf("got listen=%d upstream=%q", cfg.ListenPort, cfg.UpstreamAddr)
	}
	if cfg.HostKeyGenerated {
		t.Error("HostKeyGenerated = true, want false when the key is supplied")
	}
	if string(cfg.HostKey) != string(hostKey) {
		t.Error("supplied host key was not used verbatim")
	}
}

func TestLoadConfigIPv6UpstreamIsBracketed(t *testing.T) {
	env := validEnv(t)
	_, pub := testKey(t)
	env["SSH_UPSTREAM_HOST"] = "2001:db8::1"
	env["SSH_UPSTREAM_PORT"] = "2200"
	env["SSH_UPSTREAM_KNOWN_HOSTS_B64"] = b64([]byte("[2001:db8::1]:2200 " + string(pub)))

	cfg, _, err := LoadConfig(getenvFrom(env))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.UpstreamAddr != "[2001:db8::1]:2200" {
		t.Errorf("UpstreamAddr = %q", cfg.UpstreamAddr)
	}
}

func TestLoadConfigBase64ToleratesWhitespace(t *testing.T) {
	env := validEnv(t)
	wrapped := env["SSH_UPSTREAM_PRIVATE_KEY_B64"]
	var chunks []string
	for i := 0; i < len(wrapped); i += 64 {
		chunks = append(chunks, wrapped[i:min(i+64, len(wrapped))])
	}
	env["SSH_UPSTREAM_PRIVATE_KEY_B64"] = "\n" + strings.Join(chunks, "\n") + "\n"
	if _, _, err := LoadConfig(getenvFrom(env)); err != nil {
		t.Fatalf("LoadConfig with wrapped Base64: %v", err)
	}
}

func TestLoadConfigReportsEveryMissingVariable(t *testing.T) {
	_, _, err := LoadConfig(func(string) string { return "" })
	if err == nil {
		t.Fatal("LoadConfig succeeded with an empty environment")
	}
	for _, want := range []string{
		"SSH_UPSTREAM_HOST", "SSH_UPSTREAM_USER", "SSH_AUTHORIZED_KEY_B64",
		"SSH_UPSTREAM_PRIVATE_KEY_B64", "SSH_UPSTREAM_KNOWN_HOSTS_B64",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}

func TestLoadConfigRejectsBadInput(t *testing.T) {
	otherPriv, otherPub := testKey(t)
	tests := []struct {
		name string
		key  string
		val  string
		want string
	}{
		{"bad base64", "SSH_AUTHORIZED_KEY_B64", "!!!not base64!!!", "not valid Base64"},
		{"empty decode", "SSH_AUTHORIZED_KEY_B64", b64(nil), "is required"},
		{"not a public key", "SSH_AUTHORIZED_KEY_B64", b64(otherPriv), "SSH_AUTHORIZED_KEY_B64"},
		{"not a private key", "SSH_UPSTREAM_PRIVATE_KEY_B64", b64(otherPub), "SSH_UPSTREAM_PRIVATE_KEY_B64"},
		{"bad host key", "SSH_SERVER_HOST_KEY_B64", b64(otherPub), "SSH_SERVER_HOST_KEY_B64"},
		{"malformed known_hosts", "SSH_UPSTREAM_KNOWN_HOSTS_B64", b64([]byte("upstream.example bogus")), "SSH_UPSTREAM_KNOWN_HOSTS_B64"},
		{"known_hosts for another host", "SSH_UPSTREAM_KNOWN_HOSTS_B64", b64([]byte("other.example " + string(otherPub))), "no entry matches"},
		{"listen port not a number", "SSH_LISTEN_PORT", "http", "SSH_LISTEN_PORT"},
		{"listen port out of range", "SSH_LISTEN_PORT", "70000", "SSH_LISTEN_PORT"},
		{"upstream port zero", "SSH_UPSTREAM_PORT", "0", "SSH_UPSTREAM_PORT"},
		{"host with slash", "SSH_UPSTREAM_HOST", "example.com/x", "illegal character"},
		{"host with query", "SSH_UPSTREAM_HOST", "example.com?x", "illegal character"},
		{"host with fragment", "SSH_UPSTREAM_HOST", "example.com#x", "illegal character"},
		{"host with userinfo", "SSH_UPSTREAM_HOST", "root@example.com", "illegal character"},
		{"host with ipv6 zone", "SSH_UPSTREAM_HOST", "fe80::1%eth0", "illegal character"},
		{"user with space", "SSH_UPSTREAM_USER", "dep loy", "whitespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnv(t)
			env[tc.key] = tc.val
			_, _, err := LoadConfig(getenvFrom(env))
			if err == nil {
				t.Fatalf("LoadConfig accepted %s=%q", tc.key, tc.val)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v does not contain %q", err, tc.want)
			}
		})
	}
}

func TestLoadConfigAcceptsMultipleAuthorizedKeys(t *testing.T) {
	env := validEnv(t)
	_, a := testKey(t)
	_, b := testKey(t)
	env["SSH_AUTHORIZED_KEY_B64"] = b64([]byte(
		"# comment\n" + string(a) + "\n" + `restrict,command="/bin/true" ` + string(b) + "\n\n"))

	cfg, fp, err := LoadConfig(getenvFrom(env))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(fp.AuthorizedKeys) != 2 {
		t.Fatalf("got %d fingerprints, want 2", len(fp.AuthorizedKeys))
	}
	if strings.Contains(string(cfg.AuthorizedKeys), "#") {
		t.Error("comment line was not stripped")
	}
	if !strings.Contains(string(cfg.AuthorizedKeys), "command=") {
		t.Error("authorized_keys options were dropped")
	}
}

// sshpiper authorises certificates against trusted_user_ca_keys, never
// against authorized_keys, so a certificate must be rejected up front instead
// of producing a relay that nobody can log in to.
func TestLoadConfigRejectsUserCertificate(t *testing.T) {
	caPriv, _ := testKey(t)
	ca, err := ssh.ParsePrivateKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, userPub := testKey(t)
	user, _, _, _, err := ssh.ParseAuthorizedKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key:         user,
		CertType:    ssh.UserCert,
		KeyId:       "test",
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}

	env := validEnv(t)
	env["SSH_AUTHORIZED_KEY_B64"] = b64(ssh.MarshalAuthorizedKey(cert))
	_, _, err = LoadConfig(getenvFrom(env))
	if err == nil {
		t.Fatal("LoadConfig accepted a user certificate")
	}
	if !strings.Contains(err.Error(), "certificates are not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestRenderPipeConfigRoundTrip parses the rendered document with the same
// library and field names sshpiper's yaml plugin uses.
func TestRenderPipeConfigRoundTrip(t *testing.T) {
	env := validEnv(t)
	cfg, _, err := LoadConfig(getenvFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := cfg.RenderPipeConfig()
	if err != nil {
		t.Fatal(err)
	}

	var got piperConfig
	if err := yaml.Unmarshal(doc, &got); err != nil {
		t.Fatalf("rendered config is not valid YAML: %v\n%s", err, doc)
	}
	if got.Version != "1.0" || len(got.Pipes) != 1 || len(got.Pipes[0].From) != 1 {
		t.Fatalf("unexpected shape: %+v", got)
	}
	from, to := got.Pipes[0].From[0], got.Pipes[0].To
	if !from.UsernameRegexMatch || from.Username != anyUsernameRegex {
		t.Errorf("from = %+v", from)
	}
	if to.Host != "upstream.example:22" || to.Username != "deploy" {
		t.Errorf("to = %+v", to)
	}
	for name, pair := range map[string][2]string{
		"authorized_keys_data": {from.AuthorizedKeysData, string(cfg.AuthorizedKeys)},
		"private_key_data":     {to.PrivateKeyData, string(cfg.UpstreamKey)},
		"known_hosts_data":     {to.KnownHostsData, string(cfg.KnownHosts)},
	} {
		decoded, err := base64.StdEncoding.DecodeString(pair[0])
		if err != nil {
			t.Errorf("%s is not standard Base64: %v", name, err)
			continue
		}
		if string(decoded) != pair[1] {
			t.Errorf("%s does not round-trip", name)
		}
	}
	// No secret may leak in clear text.
	if strings.Contains(string(doc), "PRIVATE KEY") {
		t.Error("private key appears unencoded in the rendered config")
	}
}

// TestUpstreamUsernameRewrite reproduces sshpiper's MatchConn logic
// (plugin/yaml/skel.go: targetuser = re.ReplaceAllString(user, to.Username))
// to prove the catch-all pipe always yields the configured upstream user.
func TestUpstreamUsernameRewrite(t *testing.T) {
	for _, upstreamUser := range []string{"deploy", "a$1b", "$name", "$$", "user-1"} {
		t.Run(upstreamUser, func(t *testing.T) {
			env := validEnv(t)
			env["SSH_UPSTREAM_USER"] = upstreamUser
			cfg, _, err := LoadConfig(getenvFrom(env))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := cfg.RenderPipeConfig()
			if err != nil {
				t.Fatal(err)
			}
			var parsed piperConfig
			if err := yaml.Unmarshal(doc, &parsed); err != nil {
				t.Fatal(err)
			}
			from, to := parsed.Pipes[0].From[0], parsed.Pipes[0].To

			re, err := regexp.Compile(from.Username)
			if err != nil {
				t.Fatalf("sshpiper could not compile %q: %v", from.Username, err)
			}
			for _, downstream := range []string{"root", "alice", "deploy", "a", "x-y_z", upstreamUser} {
				if !re.MatchString(downstream) {
					t.Errorf("downstream user %q does not match the catch-all pipe", downstream)
					continue
				}
				if got := re.ReplaceAllString(downstream, to.Username); got != upstreamUser {
					t.Errorf("downstream %q -> upstream %q, want %q", downstream, got, upstreamUser)
				}
			}
		})
	}
}
