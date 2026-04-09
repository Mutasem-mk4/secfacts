PREFIX ?= /usr/local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin
MANDIR := $(DESTDIR)$(PREFIX)/share/man/man1
BASH_COMPLETIONDIR := $(DESTDIR)$(PREFIX)/share/bash-completion/completions
ZSH_COMPLETIONDIR := $(DESTDIR)$(PREFIX)/share/zsh/site-functions
FISH_COMPLETIONDIR := $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
TARGET := axon

.PHONY: build test vet install completion install-completions install-man proto

build:
	mkdir -p bin
	go build -o bin/$(TARGET) ./cmd/axon

test:
	go test ./...

vet:
	go vet ./...

install:
	install -d $(BINDIR)
	install -m 0755 bin/$(TARGET) $(BINDIR)/$(TARGET)

completion:
	mkdir -p bin
	./bin/$(TARGET) completion bash > bin/$(TARGET).bash
	./bin/$(TARGET) completion zsh > bin/_$(TARGET)
	./bin/$(TARGET) completion fish > bin/$(TARGET).fish

install-completions: completion
	install -d $(BASH_COMPLETIONDIR)
	install -d $(ZSH_COMPLETIONDIR)
	install -d $(FISH_COMPLETIONDIR)
	install -m 0644 bin/$(TARGET).bash $(BASH_COMPLETIONDIR)/$(TARGET)
	install -m 0644 bin/_$(TARGET) $(ZSH_COMPLETIONDIR)/_$(TARGET)
	install -m 0644 bin/$(TARGET).fish $(FISH_COMPLETIONDIR)/$(TARGET).fish

install-man:
	install -d $(MANDIR)
	install -m 0644 man/$(TARGET).1 $(MANDIR)/$(TARGET).1

proto:
	protoc --go_out=. --go-grpc_out=. api/proto/v1/axon.proto

