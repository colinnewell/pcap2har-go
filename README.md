# pcap2har-go

This is a quick stab at a replacement for pcap2har written in Go.

This is not complete, and is largely been driven by occasions where I
need to analyse packet captures.  If you want a more complete program
that does this look at https://github.com/andrewf/pcap2har.  That is a
python program using scapy that I have been using to do this before.

The idea is to detect all HTTP traffic in a packet capture and turn it
into a HAR file for simpler analysis.  Browsers commonly output har
files and it's a json is a convenient format to look through.

http://www.softwareishard.com/blog/har-12-spec/

Note that it's not going do well with TLS traffic, so this won't be
much use for most traffic you do with the outside these days.  This is
often really handy for development however.  Especially with internal
web service development.

This is largely based off the example in the documentation:

https://godoc.org/github.com/google/gopacket/tcpassembly/tcpreader

It has various limitations.

* joining up 2 sides of the conversation seems flawed.
* no timestamps

In order to fix those limitations I'd probably need to extend or redo
the existing tcpreader.

Large or sketchy packet captures may well cause problems.  The reader
doesn't really join up both sides of the conversation for me so I'm
using the address pair to link them up, but if you got a repeat, that
would go wrong.  Also I'm not really checking for dropped packets.  The
library I'm using is paying attention to things like that, so it might
be that all we do is not include those conversations in the output.
The library takes timestamps and uses them to help construct packet
captures, but doesn't provide that info when it has joined them up.

We're also loading all this data into memory before outputting it to
json.

In short, there's plenty more to do before this is complete, the code
is more a proof of concept at this point.  It is amazing how far you
can get so quickly with the existing Go libraries.
