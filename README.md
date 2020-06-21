# pcap2har-go

## Overview

This is a quick stab at a replacement for pcap2har written in Go.

This is not complete, and is largely been driven by occasions where I
need to analyse packet captures.  If you want a more complete program
that does this look at https://github.com/andrewf/pcap2har.  That is a
python program using scapy that I have been using to do this before.

The idea is to detect all HTTP traffic in a packet capture and turn it
into a HAR file for simpler analysis.  Browsers commonly output har
files and it's a json is a convenient format to look through.

http://www.softwareishard.com/blog/har-12-spec/

Note that it's not going to do well with TLS traffic, so this won't be
much use for most traffic you do with the outside these days.  This is
often really handy for development however.  Especially with internal
web service development.

This is largely based off the example in the documentation:

https://godoc.org/github.com/google/gopacket/tcpassembly/tcpreader

It has various limitations.

* joining up 2 sides of the conversation seems flawed.
* ordering of HTTP requests get grouped up by tcp connection which may 
  not match the chronological order.  It also tends to be fairly random due to
  the asynchronous nature of the goroutines.
* http details may be obscured as the libraries I'm using automatically
  decode http features like chunked encoding.  This can be really 
  useful (not having to decode base64 content), or frustrating when
  those details are what would help you spot a problem.
* I haven't looked at how you'd decode TLS traffic.  Presumably I'd
  need to provide keys for that.
* Timing info may not be perfect.  I need to test more thoroughly, but I
  suspect the time for the entry will be derived from the timing of the data
  packets, without taking into consideration the TCP handshake.

In order to fix those limitations I'd probably need to extend or redo
the existing tcpreader.

Large or sketchy packet captures may well cause problems.  The reader
doesn't really join up both sides of the conversation for me so I'm
using the address pair to link them up, but if you got a repeat, that
would go wrong.  Also I'm not really checking for dropped packets.  The
library I'm using is paying attention to things like that, so it might
be that all we do is not include those conversations in the output.

We're also loading all this data into memory before outputting it to
json.

In short, there's plenty more to do before this is complete, the code
is more a proof of concept at this point.  It is amazing how far you
can get so quickly with the existing Go libraries.

It's only been very lightly tested so far.  It really needs a lot of
work before it's production ready.

## Building

This requires the libpcap development library (and Go).

	sudo apt install libpcap-dev
	make
	sudo make install

## Using

	sudo tcpdump port 80 -w packets.dump
	pcap2har packets.dump

HAR files contain a lot of info you probably don't need.  I like to use tools
like jq to boil down the json into more concise info.

	pcap2har packets.dump | jq '.log.entries[] | { url: .request.url, response: (if .response.content.mimeType == "application/json" then .response.content.text | gsub("\n"; "") | @base64d | fromjson else "" end), response_status: .response.status, query_string: .request.queryString }'
