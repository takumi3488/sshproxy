package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSshpiperdArgs(t *testing.T) {
	env := validEnv(t)
	env["SSH_LISTEN_PORT"] = "2022"
	cfg, _, err := LoadConfig(getenvFrom(env))
	if err != nil {
		t.Fatal(err)
	}

	// Every daemon flag precedes the plugin binary: urfave/cli stops parsing
	// flags at the first positional argument.
	argv := SshpiperdArgs(cfg, "/run/x")
	want := []string{
		"/sshpiperd/sshpiperd",
		"--address", "0.0.0.0",
		"--port", "2022",
		"--server-key", "/run/x/host_key",
		"--server-key-generate-mode", "disable",
		"/sshpiperd/plugins/yaml",
		"--config", "/run/x/sshpiperd.yaml",
	}
	if !slices.Equal(argv, want) {
		t.Errorf("argv =\n%v\nwant\n%v", argv, want)
	}
}

// sshpiperd expands --server-key and the plugin expands --config with
// filepath.Glob, so a TMPDIR containing a metacharacter must still resolve.
func TestSshpiperdArgsEscapesGlobMetacharacters(t *testing.T) {
	dir := t.TempDir()
	tricky := filepath.Join(dir, "relay[prod]*?")
	if err := os.MkdirAll(tricky, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadConfig(getenvFrom(validEnv(t)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostKeyPath(tricky), cfg.HostKey, 0o600); err != nil {
		t.Fatal(err)
	}

	argv := SshpiperdArgs(cfg, tricky)
	pattern := argv[slices.Index(argv, "--server-key")+1]
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("filepath.Glob(%q): %v", pattern, err)
	}
	if len(matches) != 1 || matches[0] != hostKeyPath(tricky) {
		t.Errorf("glob of %q resolved to %v, want exactly [%s]", pattern, matches, hostKeyPath(tricky))
	}
}

func TestScrubEnv(t *testing.T) {
	got := ScrubEnv([]string{
		"PATH=/bin",
		"SSH_UPSTREAM_PRIVATE_KEY_B64=secret",
		"SSH_AUTHORIZED_KEY_B64=x",
		"SSH_UPSTREAM_KNOWN_HOSTS_B64=x",
		"SSH_SERVER_HOST_KEY_B64=secret",
		"SSHPIPERD_SERVER_KEY_GENERATE_MODE=notexist",
		"PLUGIN=workingdir",
		"SSHPIPERD_LOG_LEVEL=debug",
		"SSH_UPSTREAM_HOST=upstream.example",
	})
	want := []string{"PATH=/bin", "SSHPIPERD_LOG_LEVEL=debug", "SSH_UPSTREAM_HOST=upstream.example"}
	if !slices.Equal(got, want) {
		t.Errorf("ScrubEnv = %v, want %v", got, want)
	}
}

func TestWriteRuntimeFilesPermissions(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	cfg, _, err := LoadConfig(getenvFrom(validEnv(t)))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := writeRuntimeFiles(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{pipeConfigPath(dir), hostKeyPath(dir)} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		// The yaml plugin rejects any config with group/other permissions.
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %o, want no group/other bits", filepath.Base(path), perm)
		}
	}
	if fi, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("runtime dir has mode %o, want no group/other bits", perm)
	}

	hostKey, err := os.ReadFile(hostKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParsePrivateKey(hostKey); err != nil {
		t.Errorf("host key written for sshpiperd is unusable: %v", err)
	}
}
