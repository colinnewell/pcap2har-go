all: stats-summary

stats-summary: main.go go.mod go.sum
	go build -o pcap2har main.go

test:
	go test ./...

clean:
	rm pcap2har

install:
	cp pcap2har /usr/local/bin

lint:
	golangci-lint run
	golint ./...
