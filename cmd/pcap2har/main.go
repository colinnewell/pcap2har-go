package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"github.com/colinnewell/pcap2har-go/internal/har"
	"github.com/colinnewell/pcap2har-go/internal/reader"
	"github.com/colinnewell/pcap2har-go/internal/streamfactory"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/pflag"
)

func main() {
	var displayVersion bool

	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
	pflag.Parse()

	buildVersion := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		// NOTE: right now this probably always returns (devel).  Hopefully
		// will improve with new versions of Go.  It might be neat to add
		// dep info too at some point since that's part of the build info.
		buildVersion = bi.Main.Version
	}

	if displayVersion {
		fmt.Printf("Version: %s\n", buildVersion)
		return
	}

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

	var har har.Har
	har.Log.Version = "1.2"
	har.Log.Creator.Name = "pcap2har"
	har.Log.Creator.Version = buildVersion

	c := streamFactory.Reader.GetConversations()
	for _, v := range c {
		har.AddEntry(v)
	}
	har.FinaliseAndSort()

	bytes, err := json.Marshal(har)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bytes))
}
