module github.com/colinnewell/pcap2har-go

go 1.14

require (
	github.com/colinnewell/pcap-cli v0.0.5
	github.com/google/go-cmp v0.5.6
	github.com/google/gopacket v1.1.19
	github.com/json-iterator/go v1.1.12
	golang.org/x/net v0.0.0-20200927032502-5d4f70055728 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

//replace github.com/colinnewell/pcap-cli => ../pcap-cli
