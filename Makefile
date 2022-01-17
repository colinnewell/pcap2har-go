VERSION  := $(shell git describe --tags 2>/dev/null || git rev-parse --short HEAD)

all: pcap2har

pcap2har: cmd/pcap2har/main.go go.mod go.sum internal/reader/*.go \
			internal/har/*.go internal/streamfactory/*.go internal/go/fcgi/*
	go build -o pcap2har -ldflags "-X github.com/colinnewell/pcap-cli/cli.Version=$(VERSION)" cmd/pcap2har/*.go

test: .force e2e-test
	go test ./...

e2e-test: pcap2har
	test/e2e-tests.sh

# fake target (don't create a file or directory with this name)
# allows us to ensure a target always gets run, even if there is a folder or
# file with that name.
# This is different to doing make -B to ensure you do a rebuild.
# This is here because we have a test directory which makes the make test think
# it's 'built' already.
.force:

clean:
	rm pcap2har

install:
	cp pcap2har /usr/local/bin

lint:
	golangci-lint run
	./ensure-gofmt.sh

fuzz:
	go get github.com/dvyukov/go-fuzz/go-fuzz \
			github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build
	go-fuzz -bin fuzz-fuzz.zip
