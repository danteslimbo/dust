GO := go
GO_BUILD = CGO_ENABLED=1 $(GO) build
GO_GENERATE = $(GO) generate
GO_TAGS ?=
TARGET_GOARCH ?= amd64
GOARCH ?= amd64
VERSION=$(shell git describe --tags --always)
LIBPCAP_ARCH ?= x86_64-unknown-linux-gnu

dust: *.go */*/*.go bpf/*.c
	TARGET_GOARCH=$(TARGET_GOARCH) $(GO_GENERATE)
	CC=$(CC) GOARCH=$(TARGET_GOARCH) $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
    		-ldflags "-w -s \
    		-X 'github.com/danteslimbo/dust/internal/dust.Version=${VERSION}'"
