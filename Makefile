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
