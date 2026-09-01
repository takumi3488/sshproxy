#!/bin/sh
# End-to-end check of the relay: shell, exec, pty, scp (both protocols), sftp,
# local and remote port forwarding, plus a negative authentication test.
# Runs inside the compose "client" service: docker compose run --rm client
set -eu

RELAY_HOST=${RELAY_HOST:-relay}
RELAY_PORT=${RELAY_PORT:-2222}
UPSTREAM_USER=${UPSTREAM_USER:-app}
# Any downstream username is accepted; the relay always rewrites it.
LOGIN=${LOGIN:-anyone}
TARGET="$LOGIN@$RELAY_HOST"

KEY=/secrets/client_key
COMMON="-o IdentitiesOnly=yes -o UserKnownHostsFile=/secrets/client_known_hosts
 -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o LogLevel=ERROR"

# shellcheck disable=SC2086 # COMMON is a deliberate argument list
run_ssh() { ssh -p "$RELAY_PORT" -i "$KEY" $COMMON "$@"; }
# shellcheck disable=SC2086
run_scp() { scp -P "$RELAY_PORT" -i "$KEY" $COMMON "$@"; }
# shellcheck disable=SC2086
run_sftp() { sftp -P "$RELAY_PORT" -i "$KEY" $COMMON "$@"; }

fail=0
pass() { echo "ok   - $1"; }
fatal() {
	echo "FAIL - $1"
	fail=1
}

echo "waiting for $RELAY_HOST:$RELAY_PORT"
i=0
until nc -z "$RELAY_HOST" "$RELAY_PORT" 2>/dev/null; do
	i=$((i + 1))
	[ "$i" -lt 60 ] || {
		echo "relay never became reachable"
		exit 1
	}
	sleep 1
done

# 1. exec channel + upstream username rewriting
got=$(run_ssh "$TARGET" 'id -un')
if [ "$got" = "$UPSTREAM_USER" ]; then
	pass "exec channel, downstream '$LOGIN' -> upstream '$got'"
else
	fatal "exec channel returned '$got', want '$UPSTREAM_USER'"
fi

# 2. shell channel fed from stdin
got=$(echo 'echo SHELL_OK' | run_ssh -T "$TARGET")
[ "$got" = "SHELL_OK" ] && pass "shell channel" || fatal "shell channel returned '$got'"

# 3. pty allocation
got=$(run_ssh -tt "$TARGET" 'tty >/dev/null && echo PTY_OK' 2>/dev/null | tr -d '\r')
[ "$got" = "PTY_OK" ] && pass "pty session" || fatal "pty session returned '$got'"

# 4. scp over the SFTP protocol (OpenSSH >= 9 default) and the legacy protocol
head -c 65536 /dev/urandom >/tmp/payload
for mode in sftp legacy; do
	[ "$mode" = legacy ] && o=-O || o=
	rm -f /tmp/payload.back
	if run_scp $o -q /tmp/payload "$TARGET:/tmp/payload.$mode" &&
		run_scp $o -q "$TARGET:/tmp/payload.$mode" /tmp/payload.back &&
		cmp -s /tmp/payload /tmp/payload.back; then
		pass "scp round trip ($mode protocol)"
	else
		fatal "scp round trip ($mode protocol)"
	fi
done

# 5. sftp subsystem
rm -f /tmp/payload.sftpget
if printf 'put /tmp/payload /tmp/payload.sftpput\nget /tmp/payload.sftpput /tmp/payload.sftpget\nbye\n' |
	run_sftp -q -b - "$TARGET" >/dev/null &&
	cmp -s /tmp/payload /tmp/payload.sftpget; then
	pass "sftp subsystem round trip"
else
	fatal "sftp subsystem round trip"
fi

# 6. local forwarding (direct-tcpip): tunnel to the upstream's own sshd
run_ssh -M -S /tmp/ctl-l -f -N -o ExitOnForwardFailure=yes \
	-L 127.0.0.1:19022:127.0.0.1:22 "$TARGET"
got=$(nc -w 3 127.0.0.1 19022 </dev/null | head -1 | tr -d '\r')
run_ssh -S /tmp/ctl-l -O exit "$TARGET" 2>/dev/null
case "$got" in
SSH-2.0-*) pass "local forwarding -L ($got)" ;;
*) fatal "local forwarding -L returned '$got'" ;;
esac

# 7. remote forwarding (tcpip-forward + forwarded-tcpip)
token="REMOTE_FORWARD_OK_$$"
(echo "$token" | nc -l -p 19222 >/dev/null 2>&1) &
listener=$!
i=0
until netstat -ltn 2>/dev/null | grep -q '127.0.0.1:19222\|:::19222\|0.0.0.0:19222'; do
	i=$((i + 1))
	[ "$i" -lt 100 ] || {
		fatal "local listener never came up"
		break
	}
	sleep 0.1
done
run_ssh -M -S /tmp/ctl-r -f -N -o ExitOnForwardFailure=yes \
	-R 127.0.0.1:19122:127.0.0.1:19222 "$TARGET"
got=$(run_ssh "$TARGET" 'nc -w 3 127.0.0.1 19122 </dev/null' | tr -d '\r')
run_ssh -S /tmp/ctl-r -O exit "$TARGET" 2>/dev/null
kill "$listener" 2>/dev/null || true
[ "$got" = "$token" ] && pass "remote forwarding -R" || fatal "remote forwarding -R returned '$got'"

# 8. an unauthorised client key must be rejected
if (
	KEY=/secrets/upstream_key
	run_ssh -o BatchMode=yes "$TARGET" true 2>/dev/null
); then
	fatal "an unauthorised key was accepted"
else
	pass "unauthorised client key rejected"
fi

[ "$fail" -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit "$fail"
