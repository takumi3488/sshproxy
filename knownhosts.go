package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// probeAddr satisfies net.Addr for the coverage probe below; the knownhosts
// callback dereferences the remote address even when it prefers the hostname.
type probeAddr string

func (a probeAddr) Network() string { return "tcp" }
func (a probeAddr) String() string  { return string(a) }

// ValidateKnownHosts checks that data parses and contains at least one entry
// for addr ("host:port").
//
// Parsing and matching are delegated to golang.org/x/crypto/ssh/knownhosts,
// the package sshpiper itself uses at connection time, so this preflight
// accepts exactly the files that will work later. The library only reads from
// files, hence the short-lived temporary copy; known_hosts data is public.
func ValidateKnownHosts(data []byte, addr string) error {
	callback, err := knownHostsCallback(data)
	if err != nil {
		return err
	}

	// An unrelated key: the callback reports every entry it found for the
	// address in KeyError.Want, which is the coverage signal.
	probe, err := probeKey()
	if err != nil {
		return err
	}

	var keyErr *knownhosts.KeyError
	switch err := callback(addr, probeAddr(addr), probe); {
	case err == nil:
		return nil
	case errors.As(err, &keyErr) && len(keyErr.Want) > 0:
		return nil
	case errors.As(err, &keyErr):
		return fmt.Errorf("no entry matches %s; expected a line for %q",
			addr, knownhosts.Normalize(addr))
	default:
		return err
	}
}

func knownHostsCallback(data []byte) (ssh.HostKeyCallback, error) {
	f, err := os.CreateTemp("", "sshproxy-known_hosts-")
	if err != nil {
		return nil, fmt.Errorf("create temporary known_hosts: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()

	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return nil, fmt.Errorf("write temporary known_hosts: %w", err)
	}

	callback, err := knownhosts.New(f.Name())
	if err != nil {
		// Parse errors embed the file name; the caller only knows the
		// environment variable it came from.
		return nil, errors.New(strings.ReplaceAll(err.Error(), f.Name(), "known_hosts"))
	}
	return callback, nil
}

func probeKey() (ssh.PublicKey, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(pub)
}
