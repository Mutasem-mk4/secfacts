PREFIX ?= /usr/local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin
TARGET := secfacts

.PHONY: build test install completion

build:
	mkdir -p bin
	go build -o bin/$(TARGET) ./cmd/secfacts

test:
	go test ./...

install:
	install -d $(BINDIR)
	install -m 0755 bin/$(TARGET) $(BINDIR)/$(TARGET)

completion:
	mkdir -p bin
	./bin/$(TARGET) completion bash > bin/$(TARGET).bash
	./bin/$(TARGET) completion zsh > bin/_$(TARGET)
	./bin/$(TARGET) completion fish > bin/$(TARGET).fish
