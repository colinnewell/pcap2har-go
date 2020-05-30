all: pcap2har

pcap2har: cmd/pcap2har/main.go go.mod go.sum internal/reader/reader.go \
			internal/har/har.go internal/streamfactory/factory.go
	go build -o pcap2har cmd/pcap2har/main.go

test: pcap2har .force
	go test ./...
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
	golint ./...

fuzz:
	go get github.com/dvyukov/go-fuzz/go-fuzz \
			github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build
	go-fuzz -bin fuzz-fuzz.zip
