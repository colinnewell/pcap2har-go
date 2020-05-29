package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/colinnewell/pcap2har-go/internal/har"
	"github.com/colinnewell/pcap2har-go/internal/reader"
	"github.com/colinnewell/pcap2har-go/internal/streamfactory"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func main() {
	files := os.Args[1:]

	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	streamFactory := &streamfactory.HTTPStreamFactory{
		Reader: reader.New(),
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for _, filename := range files {
		if handle, err := pcap.OpenOffline(filename); err != nil {
			log.Fatal(err)
		} else {
			defer handle.Close()
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

	assembler.FlushAll()
	//fmt.Printf("Found %d connections\n", connections)
	c := streamFactory.Reader.GetConversations()
	var har har.Har
	for _, v := range c {
		har.AddEntry(v)
	}

	bytes, err := json.Marshal(har)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bytes))
}
