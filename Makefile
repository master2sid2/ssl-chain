# Read version from VERSION file
VERSION := $(shell cat VERSION)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    := $(shell date -u +%Y-%m-%d)

BINARY  := ssl_chain
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# ─── Targets ──────────────────────────────────────────────────────────────────

.PHONY: build clean install version help

## build: compile the binary
build:
	go build $(LDFLAGS) -o build/bin/$(BINARY)-v$(VERSION) .

## install: install to /usr/local/bin
install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

## clean: remove built binary
clean:
	rm -f build/bin/$(BINARY)-v$(VERSION)

## version: print current version
version:
	@echo "Version : $(VERSION)"
	@echo "Commit  : $(COMMIT)"
	@echo "Date    : $(DATE)"

## help: show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^## ' Makefile | sed 's/## /  /'
