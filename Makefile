all: pcap2har

pcap2har: cmd/pcap2har/main.go go.mod go.sum internal/reader/reader.go
	go build -o pcap2har cmd/pcap2har/main.go

test:
	go test ./...

clean:
	rm pcap2har

install:
	cp pcap2har /usr/local/bin

lint:
	golangci-lint run
	golint ./...

fuzz:
	go get github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build
	go-fuzz -bin fuzz-fuzz.zip
