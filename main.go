// Command sshproxy is a launcher for sshpiperd.
//
// It reads every setting from the environment, validates the SSH key material,
// renders an ephemeral sshpiper yaml-plugin configuration into a private
// temporary directory and then execs sshpiperd in place.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

const (
	sshpiperdBin  = "/sshpiperd/sshpiperd"
	yamlPluginBin = "/sshpiperd/plugins/yaml"
)

// scrubbedEnv lists variables removed before exec: our own secret inputs (so
// they are not exposed through the daemon's and plugin's /proc/*/environ) and
// sshpiperd settings that this launcher owns via explicit flags.
var scrubbedEnv = []string{
	"SSH_AUTHORIZED_KEY_B64",
	"SSH_UPSTREAM_PRIVATE_KEY_B64",
	"SSH_UPSTREAM_KNOWN_HOSTS_B64",
	"SSH_SERVER_HOST_KEY_B64",
	"PLUGIN",
	"SSHPIPERD_ADDRESS",
	"SSHPIPERD_PORT",
	"SSHPIPERD_SERVER_KEY",
	"SSHPIPERD_SERVER_KEY_DATA",
	"SSHPIPERD_SERVER_CERT",
	"SSHPIPERD_SERVER_CERT_DATA",
	"SSHPIPERD_SERVER_KEY_GENERATE_MODE",
	"SSHPIPERD_YAML_CONFIG",
	"SSHPIPERD_YAML_NOCHECKPERM",
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("sshproxy: ")
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, fp, err := LoadConfig(os.Getenv)
	if err != nil {
		return err
	}

	dir, err := writeRuntimeFiles(cfg)
	if err != nil {
		return err
	}

	for _, f := range fp.AuthorizedKeys {
		log.Printf("client key accepted: %s", f)
	}
	log.Printf("upstream %s@%s, key %s", cfg.UpstreamUser, cfg.UpstreamAddr, fp.UpstreamKey)
	if cfg.HostKeyGenerated {
		log.Printf("host key %s (ephemeral, generated at startup)", fp.HostKey)
	} else {
		log.Printf("host key %s", fp.HostKey)
	}
	log.Printf("listening on 0.0.0.0:%d", cfg.ListenPort)

	argv := SshpiperdArgs(cfg, dir)
	return syscall.Exec(argv[0], argv, ScrubEnv(os.Environ()))
}

// writeRuntimeFiles materialises the generated configuration in a private
// temporary directory. Nothing is written to a path that could be baked into
// an image; set TMPDIR to a tmpfs to keep secrets off disk entirely.
func writeRuntimeFiles(cfg *Config) (string, error) {
	dir, err := os.MkdirTemp("", "sshproxy-")
	if err != nil {
		return "", fmt.Errorf("create runtime directory: %w", err)
	}

	pipeConfig, err := cfg.RenderPipeConfig()
	if err != nil {
		return "", fmt.Errorf("render sshpiper config: %w", err)
	}
	// The yaml plugin refuses configs with group/other permission bits.
	if err := os.WriteFile(pipeConfigPath(dir), pipeConfig, 0o600); err != nil {
		return "", fmt.Errorf("write sshpiper config: %w", err)
	}
	if err := os.WriteFile(hostKeyPath(dir), cfg.HostKey, 0o600); err != nil {
		return "", fmt.Errorf("write host key: %w", err)
	}
	return dir, nil
}

func pipeConfigPath(dir string) string { return filepath.Join(dir, "sshpiperd.yaml") }
func hostKeyPath(dir string) string    { return filepath.Join(dir, "host_key") }

// SshpiperdArgs builds the sshpiperd argv. Daemon flags come first; the
// trailing positional argument is the plugin binary plus its own flags.
// Both consumers expand their path argument with filepath.Glob, so the
// generated paths are escaped.
func SshpiperdArgs(cfg *Config, dir string) []string {
	return []string{
		sshpiperdBin,
		"--address", "0.0.0.0",
		"--port", strconv.Itoa(cfg.ListenPort),
		"--server-key", globEscape(hostKeyPath(dir)),
		"--server-key-generate-mode", "disable",
		yamlPluginBin,
		"--config", globEscape(pipeConfigPath(dir)),
	}
}

// globEscape quotes the filepath.Match metacharacters in a literal path.
var globEscaper = strings.NewReplacer(`*`, `\*`, `?`, `\?`, `[`, `\[`, `\`, `\\`)

func globEscape(path string) string { return globEscaper.Replace(path) }

// ScrubEnv removes secret and conflicting variables from an environment slice.
func ScrubEnv(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(scrubbedEnv, name) {
			out = append(out, kv)
		}
	}
	return out
}
