#!/bin/sh
# Generates the key material for the local docker compose example and writes
# example/.env. Everything lands in example/secrets/, which is gitignored.
# The values here must stay in sync with compose.yaml and the upstream fixture.
set -eu

cd "$(dirname "$0")"

RELAY_PORT=2222
UPSTREAM_HOST=upstream
UPSTREAM_PORT=22
UPSTREAM_USER=app

mkdir -p secrets
chmod 700 secrets

gen() {
	if [ ! -f "secrets/$1" ] || [ ! -f "secrets/$1.pub" ]; then
		rm -f "secrets/$1" "secrets/$1.pub"
		ssh-keygen -q -t ed25519 -N '' -C "$1" -f "secrets/$1"
	fi
}

# client_key        : client -> relay          (SSH_AUTHORIZED_KEY_B64)
# upstream_key      : relay  -> upstream       (SSH_UPSTREAM_PRIVATE_KEY_B64)
# upstream_host_key : upstream host identity   (SSH_UPSTREAM_KNOWN_HOSTS_B64)
# relay_host_key    : relay host identity      (SSH_SERVER_HOST_KEY_B64)
gen client_key
gen upstream_key
gen upstream_host_key
gen relay_host_key
chmod 600 secrets/*

b64() { base64 <"$1" | tr -d '\n'; }

printf '%s %s\n' "$UPSTREAM_HOST" "$(cat secrets/upstream_host_key.pub)" >secrets/upstream_known_hosts
printf '[relay]:%s %s\n' "$RELAY_PORT" "$(cat secrets/relay_host_key.pub)" >secrets/client_known_hosts

rm -f .env
umask 077
cat >.env <<EOF
SSH_AUTHORIZED_KEY_B64=$(b64 secrets/client_key.pub)
SSH_UPSTREAM_PRIVATE_KEY_B64=$(b64 secrets/upstream_key)
SSH_UPSTREAM_HOST=$UPSTREAM_HOST
SSH_UPSTREAM_PORT=$UPSTREAM_PORT
SSH_UPSTREAM_USER=$UPSTREAM_USER
SSH_UPSTREAM_KNOWN_HOSTS_B64=$(b64 secrets/upstream_known_hosts)
SSH_LISTEN_PORT=$RELAY_PORT
SSH_SERVER_HOST_KEY_B64=$(b64 secrets/relay_host_key)
EOF

echo "wrote example/.env and example/secrets/"
