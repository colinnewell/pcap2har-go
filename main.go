package main

import (
	"bufio"
	"bytes"
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
	go printRequests(&r, a, b)
	return &r
}

func printRequests(r io.Reader, a, b gopacket.Flow) {
	var alt bytes.Buffer
	tee := io.TeeReader(r, &alt)
	buf := bufio.NewReader(tee)

	for {
		if req, err := http.ReadRequest(buf); err == io.EOF {
			return
		} else if err != nil {
			m := io.MultiReader(&alt, buf)
			buf := bufio.NewReader(m)
			if res, err := http.ReadResponse(buf, nil); err == io.EOF {
				return
			} else if err != nil {
				// meh, guess it's not for us.
			} else {
				fmt.Println(a, b)
				fmt.Println("HTTP RESPONSE:", res)
				fmt.Println("Body contains", tcpreader.DiscardBytesToEOF(res.Body), "bytes")
				// FIXME: grab body
				// dump whole lots as json
			}
		} else {
			fmt.Println(a, b)
			fmt.Println("HTTP REQUEST:", req)
			// FIXME: grab body
			// dump whole lots as json
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
				// NOTE: just pushing all TCP through it on the basis it might
				// be http.
				if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
					assembler.AssembleWithTimestamp(
						packet.NetworkLayer().NetworkFlow(),
						tcp, packet.Metadata().Timestamp)
				}
			}
		}
	}

	connections := assembler.FlushAll()
	fmt.Printf("Found %d connections\n", connections)
}
