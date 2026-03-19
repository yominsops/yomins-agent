VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X github.com/yominsops/yomins-agent/internal/version.Version=$(VERSION) \
           -X github.com/yominsops/yomins-agent/internal/version.Commit=$(COMMIT) \
           -X github.com/yominsops/yomins-agent/internal/version.BuildDate=$(DATE)

BINARY := yomins-agent

.PHONY: build test test-integration lint docker clean install

build:
	go build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/yomins-agent/

test:
	go test ./...

test-integration:
	go test -tags=integration -v ./...

lint:
	golangci-lint run ./...

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t yomins-agent:$(VERSION) \
		-t yomins-agent:latest \
		.

clean:
	rm -f $(BINARY)

install: build
	install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	install -m 644 systemd/yomins-agent.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Installed. Edit /etc/yomins-agent/env, then: systemctl enable --now yomins-agent"
