FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build \
    -ldflags="-s -w \
      -X github.com/yominsops/yomins-agent/internal/version.Version=${VERSION} \
      -X github.com/yominsops/yomins-agent/internal/version.Commit=${COMMIT} \
      -X github.com/yominsops/yomins-agent/internal/version.BuildDate=${DATE}" \
    -o /yomins-agent \
    ./cmd/yomins-agent/

# Use distroless for a minimal, secure image.
FROM gcr.io/distroless/static-debian12

COPY --from=builder /yomins-agent /usr/local/bin/yomins-agent

ENTRYPOINT ["/usr/local/bin/yomins-agent"]
