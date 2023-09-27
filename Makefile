.PHONY: build install

all: build

build:
	@go build .

install: build
	@go install -v
