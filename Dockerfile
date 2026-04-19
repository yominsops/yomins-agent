# syntax=docker/dockerfile:1.7

############################
# Builder
############################
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build args from CI
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Prepare state directory (copied into runtime image with correct ownership)
RUN mkdir -p /state

# Build binary
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build \
      -trimpath \
      -ldflags="-s -w \
        -X github.com/yominsops/yomins-agent/internal/version.Version=${VERSION} \
        -X github.com/yominsops/yomins-agent/internal/version.Commit=${COMMIT} \
        -X github.com/yominsops/yomins-agent/internal/version.BuildDate=${DATE}" \
      -o /out/yomins-agent \
      ./cmd/yomins-agent/

############################
# Runtime
############################
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/yomins-agent /usr/local/bin/yomins-agent
# Create the state directory owned by nonroot (UID/GID 65532) so that Docker
# initialises the named volume with the correct ownership on first use.
COPY --from=builder --chown=65532:65532 /state /var/lib/yomins/agent

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/yomins-agent"]
