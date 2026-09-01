# Test-only SSH client used by example/verify.sh.
FROM alpine:3.22

RUN apk add --no-cache openssh-client

COPY verify.sh /verify.sh
ENTRYPOINT ["/bin/sh", "/verify.sh"]
