# pcap2har-go

This is a quick stab at a replacement for pcap2har written in Go.

This is largely based off the example in the documentation:

https://godoc.org/github.com/google/gopacket/tcpassembly/tcpreader

It has various limitations.

* joining up 2 sides of the conversation seems deeply flawed.
* no timestamps

In order to fix those limitations I'd probably need to extend or redo the
existing tcpreader.


