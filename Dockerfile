FROM golang:buster AS build

RUN apt-get update && apt-get install -y libpcap-dev jq

COPY go.mod go.sum /src/pcap2har-go/
COPY cmd /src/pcap2har-go/cmd/
COPY internal /src/pcap2har-go/internal/
COPY test /src/pcap2har-go/test/

WORKDIR /src/pcap2har-go

RUN go build -o pcap2har cmd/pcap2har/main.go

FROM build AS test

RUN go test ./... && \
	test/e2e-tests.sh

FROM build AS lint

RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.27.0 \
    && go get -u golang.org/x/lint/golint
COPY .golangci.yml /.golangci.yml
RUN /go/bin/golangci-lint run # && /go/bin/golint

FROM debian:buster-slim AS binary

RUN apt-get update && apt-get install -y libpcap-dev
COPY --from=build /src/pcap2har-go/pcap2har /pcap2har

ENTRYPOINT ["/pcap2har"]
