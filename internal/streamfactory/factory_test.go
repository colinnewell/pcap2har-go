package streamfactory_test

import (
	"testing"

	"github.com/colinnewell/pcap2har-go/internal/reader"
	"github.com/colinnewell/pcap2har-go/internal/streamfactory"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func TestHTTPStreamRead(t *testing.T) {
	r := reader.New()
	streamFactory := &streamfactory.HTTPStreamFactory{
		Reader: r,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	if handle, err := pcap.OpenOffline("../../test/captures/insecure.pcap"); err != nil {
		t.Error(err)
	} else {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
				assembler.AssembleWithTimestamp(
					packet.NetworkLayer().NetworkFlow(),
					tcp, packet.Metadata().Timestamp)
			}
		}
	}
	assembler.FlushAll()
	c := r.GetConversations()
	// this is a pretty crude test, just checking we have
	// managed to do something, rather than the integrity.
	if len(c) != 21 {
		t.Errorf("Should have read 21 http conversations: read %d", len(c))
	}
}
