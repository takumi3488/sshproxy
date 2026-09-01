# sshproxy

A single-container SSH relay built on [sshpiper](https://github.com/tg123/sshpiper).

Clients authenticate to the relay with a public key. The relay then opens its
own connection to the upstream SSH server with a **different** private key and
verifies the upstream host key against a `known_hosts` file. Everything after
authentication is piped at the SSH packet level, so shell, `exec`, `scp`,
`sftp` and TCP port forwarding all pass through unchanged.

```
client --(client key)--> sshproxy --(upstream key, known_hosts verified)--> upstream sshd
```

Everything is configured through environment variables; multi-line values are
Base64-encoded. The container runs as UID 1000 and needs no root privileges.

## Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `SSH_AUTHORIZED_KEY_B64` | yes | | Base64 of an `authorized_keys` file. Every non-comment line must be a valid public key; options such as `restrict` or `command=` are preserved. User certificates are rejected: sshpiper matches those against a CA list, not against `authorized_keys`. |
| `SSH_UPSTREAM_PRIVATE_KEY_B64` | yes | | Base64 of the PEM private key used towards the upstream. Passphrase-protected keys are rejected. |
| `SSH_UPSTREAM_HOST` | yes | | Upstream hostname or IP, restricted to letters, digits and `.-_:`. IPv6 is written unbracketed, e.g. `2001:db8::1`; scoped addresses such as `fe80::1%eth0` are not supported. |
| `SSH_UPSTREAM_PORT` | no | `22` | Upstream port. |
| `SSH_UPSTREAM_USER` | yes | | Username presented to the upstream. |
| `SSH_UPSTREAM_KNOWN_HOSTS_B64` | yes | | Base64 of a `known_hosts` file that must contain an entry for the upstream. |
| `SSH_LISTEN_PORT` | no | `2222` | Port the relay listens on. Ports below 1024 need extra privileges. |
| `SSH_SERVER_HOST_KEY_B64` | no | generated | Base64 of the PEM private key the relay presents to clients. When unset, an ed25519 key is generated at startup and is **lost on restart**. |
| `SSHPIPERD_LOG_LEVEL` | no | `info` | Passed through to sshpiperd: `debug`, `info`, `warn`, `error`. |
| `TMPDIR` | no | `/tmp` | Where the generated configuration is written. Point it at a tmpfs to keep secrets off disk. |

Base64 values may contain line breaks; they are stripped before decoding.

Any downstream username is accepted, so `ssh relay-host` works regardless of
the client's local username. The relay always rewrites it to
`SSH_UPSTREAM_USER`.

### Preparing the values

```sh
b64() { base64 | tr -d '\n'; }   # on Linux, `base64 -w0` does the same

export SSH_AUTHORIZED_KEY_B64="$(b64 < ~/.ssh/id_ed25519.pub)"
export SSH_UPSTREAM_PRIVATE_KEY_B64="$(b64 < ./relay_to_upstream_ed25519)"
export SSH_UPSTREAM_KNOWN_HOSTS_B64="$(ssh-keyscan -p 22 upstream.example | b64)"
```

`known_hosts` entries must name the same host and port the relay dials. For a
non-default port the entry is `[upstream.example]:2222 ssh-ed25519 AAAA...`;
`ssh-keyscan -p 2222` already writes that form. Parsing and matching use
`golang.org/x/crypto/ssh/knownhosts`, the same package sshpiper uses at
connection time, so the launcher refuses to start on a file that would fail
later: a typo fails immediately instead of at the first connection.

## Running

```sh
docker build -t sshproxy .
docker run --rm -p 2222:2222 \
  --read-only --tmpfs /tmp:mode=1777,size=1m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -e SSH_AUTHORIZED_KEY_B64 \
  -e SSH_UPSTREAM_PRIVATE_KEY_B64 \
  -e SSH_UPSTREAM_HOST=upstream.example \
  -e SSH_UPSTREAM_USER=app \
  -e SSH_UPSTREAM_KNOWN_HOSTS_B64 \
  sshproxy
```

Then:

```sh
ssh -p 2222 localhost
scp -P 2222 file localhost:/tmp/
sftp -P 2222 localhost
ssh -p 2222 -L 8080:127.0.0.1:80 -N localhost
```

## Local end-to-end example

```sh
./example/gen-keys.sh                    # keys + example/.env
docker compose up -d --build             # upstream sshd + relay
docker compose run --rm --build client   # runs example/client/verify.sh
```

`verify.sh` runs every check and exits non-zero if any of them fails:

```
ok   - exec channel, downstream 'anyone' -> upstream 'app'
ok   - shell channel
ok   - pty session
ok   - scp round trip (sftp protocol)
ok   - scp round trip (legacy protocol)
ok   - sftp subsystem round trip
ok   - local forwarding -L (SSH-2.0-OpenSSH_10.0)
ok   - remote forwarding -R
ok   - unauthorised client key rejected
ALL CHECKS PASSED
```

Tear down with `docker compose down`. `example/secrets/` and `example/.env`
are gitignored.

## How it works

`sshproxy` is a launcher, not a proxy. At startup it:

1. reads and validates every variable, reporting all problems at once;
2. Base64-decodes the blobs and parses each key with `golang.org/x/crypto/ssh`;
3. checks with `x/crypto/ssh/knownhosts` — the package sshpiper uses at
   connection time — that the `known_hosts` data parses and actually covers
   the upstream address;
4. generates an ed25519 host key if none was supplied;
5. writes a sshpiper *yaml plugin* configuration and the host key into a fresh
   `0700` directory under `TMPDIR`, both files `0600`;
6. removes the secret variables from the environment and `exec`s
   `sshpiperd`, which becomes PID 1.

The generated configuration inlines all key material as Base64
(`authorized_keys_data`, `private_key_data`, `known_hosts_data`), so nothing is
baked into the image and no secret file survives the container.

Startup logs the SHA256 fingerprint of every key so the deployment can be
audited without exposing key material:

```
sshproxy: client key accepted: SHA256:+YYfrHYCLFjOlSTjapRKK2zQziPfCZT/zCwGoa1OKHQ
sshproxy: upstream app@upstream:22, key SHA256:lDvox1plaYX7JzjXbNIl41YlVEEIvjh7m4LrTxt9S7M
sshproxy: host key SHA256:+0xBk1yw0nkML/JrebHY1hdFUZMXRq+SntEUwfoQhcA
sshproxy: listening on 0.0.0.0:2222
```

## Security notes

- Upstream host key verification is always on. sshpiper only skips it when no
  `known_hosts` is configured, and this launcher makes that variable mandatory.
- The relay does not offer password authentication to clients: the pipe is
  configured with `authorized_keys_data`, which selects public key
  authentication in the yaml plugin.
- Secrets never reach the process command line, and the launcher unsets
  `SSH_*_B64` before `exec` so they are not readable through
  `/proc/<pid>/environ` of `sshpiperd` or of the plugin child process.
- The image runs as UID 1000, works with a read-only root filesystem and with
  all capabilities dropped.
- Supply `SSH_SERVER_HOST_KEY_B64` in production. Without it every restart
  presents a new host key and clients will report a changed identity.
- Client-side restrictions (`command=`, `restrict`, ...) in
  `SSH_AUTHORIZED_KEY_B64` are only carried to sshpiper's authentication step;
  they are not enforced by the upstream server. Enforce policy upstream.

## Development

```sh
go vet ./...
go test ./...
```

The tests cover environment validation, Base64 and key parsing, `known_hosts`
parsing and coverage (wildcards, ports, hashed hostnames, `@revoked` and
`@cert-authority` markers), the rendered yaml plugin document, file
permissions, the glob-safe `sshpiperd` argv, and environment scrubbing. The
username rewriting test
reproduces sshpiper's own `regexp.ReplaceAllString` logic to prove the
catch-all pipe always yields the configured upstream user.
