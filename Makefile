VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   = -s -w \
            -X main.version=$(VERSION) \
            -X main.commit=$(COMMIT) \
            -X main.date=$(DATE)

.PHONY: build install test cover clean

build:
	go build -ldflags "$(LDFLAGS)" -o authprobe ./cmd/authprobe

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/authprobe

test:
	go test -v -count=1 ./...

cover:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

clean:
	rm -f authprobe coverage.out
