# Test-only upstream SSH server. Not part of the relay image.
FROM alpine:3.22

# openssh-client is needed for /usr/bin/scp, which `scp -O` (legacy protocol)
# runs on this side; openssh-server does not ship it.
# adduser -D leaves the account password-locked, which sshd rejects even for
# public key authentication.
RUN apk add --no-cache openssh-server openssh-client \
 && adduser -D -s /bin/sh app \
 && sed -i 's/^app:!/app:*/' /etc/shadow \
 && mkdir -p /etc/ssh/authorized_keys

COPY sshd_config /etc/ssh/sshd_config

HEALTHCHECK --interval=2s --timeout=2s --retries=15 CMD nc -z 127.0.0.1 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
