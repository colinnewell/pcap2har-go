FROM golang:buster

RUN apt-get update && apt-get install -y libpcap-dev

COPY *.go go.sum /go/src/github.com/colinnewell/stats-summary/
WORKDIR /go/src/github.com/colinnewell/stats-summary
RUN go get && go build -o /stats-summary main.go
ENTRYPOINT "/stats-summary"
