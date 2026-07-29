GO ?= go
BINARY ?= susu
PACKAGE ?= ./cmd/susu
GOFLAGS ?=
LDFLAGS ?= -s -w -buildid=

.PHONY: all build install clean

all: build

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) \
		-trimpath \
		-buildvcs=false \
		-ldflags='$(LDFLAGS)' \
		-o ./$(BINARY) \
		$(PACKAGE)

install:
	CGO_ENABLED=0 $(GO) install $(GOFLAGS) \
		-trimpath \
		-buildvcs=false \
		-ldflags='$(LDFLAGS)' \
		$(PACKAGE)

clean:
	rm -f ./$(BINARY)
