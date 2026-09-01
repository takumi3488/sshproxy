FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sshproxy .

# The yaml plugin ships only in the "full" flavour of the image.
# /sshpiperd/sshpiperd, /sshpiperd/plugins/yaml, USER 1000:1000.
FROM ghcr.io/tg123/sshpiperd:full@sha256:362b56c67c925460cb7f788a0bf94d555c827a4dd57794b914b8bc5b9c6afead

COPY --from=builder /out/sshproxy /sshproxy

# The launcher owns these; keep the base image defaults from interfering.
ENV PLUGIN="" \
    SSHPIPERD_SERVER_KEY_GENERATE_MODE=""

USER 1000:1000
EXPOSE 2222
ENTRYPOINT ["/sshproxy"]
