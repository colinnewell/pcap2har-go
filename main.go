package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type httpStreamFactory struct{}

func (f *httpStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go printRequests(&r)
	return &r
}

func printRequests(r io.Reader) {
	// Convert to bufio, since that's what ReadRequest wants.
	buf := bufio.NewReader(r)
	for {
		if req, err := http.ReadRequest(buf); err == io.EOF {
			return
		} else if err != nil {
			//log.Println("Error parsing HTTP requests:", err)
		} else {
			fmt.Println("HTTP REQUEST:", req)
			fmt.Println("Body contains", tcpreader.DiscardBytesToEOF(req.Body), "bytes")
		}
	}
}

func main() {
	files := os.Args[1:]

	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for _, filename := range files {
		if handle, err := pcap.OpenOffline(filename); err != nil {
			log.Fatal(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			for packet := range packetSource.Packets() {
				// check for TCP
				if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
					assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
				}
			}
		}
	}

	connections := assembler.FlushAll()
	fmt.Printf("Found %d connections\n", connections)
}
