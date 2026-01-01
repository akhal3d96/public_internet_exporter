.PHONY: test

GO ?= go

test:
	$(GO) test -v ./...
