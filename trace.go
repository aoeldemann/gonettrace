package gonettrace

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Trace struct {
	pktSource *gopacket.PacketSource
}

// TraceOpen opens a PCAP network trace and returns an instance of the 'Trace'
// struct. The function expects the PCAP trace's filename and its link type.
func TraceOpen(pcapFname string, pcapLinkType layers.LinkType) *Trace {
	// create a new trace
	var trace Trace

	// open pcap file
	handlePCAP, err := pcap.OpenOffline(pcapFname)
	if err != nil {
		panic(err)
	}

	// create pcap packet source
	trace.pktSource = gopacket.NewPacketSource(handlePCAP, pcapLinkType)

	// return trace instance
	return &trace
}

// Packets returns a channel of packets for easy iteration.
func (trace *Trace) Packets() chan gopacket.Packet {
	return trace.pktSource.Packets()
}
