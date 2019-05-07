package gonettrace

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FlowIP contains the fields that identify the L3 IP portion of a flow.
type FlowIP struct {
	version int
	daddr   net.IP
	saddr   net.IP
	proto   layers.IPProtocol
}

// FlowL4 contains the fields that identify the L4 TCP/UDP portion of a flow.
type FlowL4 struct {
	dport uint16
	sport uint16
}

// Flow bundles a flow's IP fields and optionally the L4 TCP/UDP fields.
type Flow struct {
	ip *FlowIP
	l4 *FlowL4
}

// FlowCreate creates a flow from a packet based on IP and TCP/UDP headers.
func FlowCreate(pkt gopacket.Packet) *Flow {
	// get packet network layer and make sure it exists
	netlayer := pkt.NetworkLayer()
	if netlayer == nil {
		panic("trace packet does not have network layer")
	}

	// initialize flow variable
	var flow *Flow

	// get packet transport layer
	translayer := pkt.TransportLayer()

	if netlayer.LayerType() == layers.LayerTypeIPv4 {
		// IPv4
		ip4 := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		if translayer == nil {
			flow = createFlowIP(4, ip4.DstIP, ip4.SrcIP, ip4.Protocol)
		} else if ip4.Protocol == layers.IPProtocolIPv6 {
			// ipv6 packet encapsulated in ipv4 packet -> this should not
			// happen
			panic("trace contains ipv6-in-ipv4 packet")
		} else {
			if translayer.LayerType() == layers.LayerTypeTCP {
				tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
				flow = createFlowIPTCPUDP(4, ip4.DstIP, ip4.SrcIP, ip4.Protocol, uint16(tcp.DstPort), uint16(tcp.SrcPort))
			} else if translayer.LayerType() == layers.LayerTypeUDP {
				udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
				flow = createFlowIPTCPUDP(4, ip4.DstIP, ip4.SrcIP, ip4.Protocol, uint16(udp.DstPort), uint16(udp.SrcPort))
			} else {
				flow = createFlowIP(4, ip4.DstIP, ip4.SrcIP, ip4.Protocol)
			}
		}
	} else if netlayer.LayerType() == layers.LayerTypeIPv6 {
		//IPv6
		ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)

		if translayer == nil {
			flow = createFlowIP(6, ip6.DstIP, ip6.SrcIP, ip6.NextHeader)
		} else {
			if translayer.LayerType() == layers.LayerTypeTCP {
				tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
				flow = createFlowIPTCPUDP(6, ip6.DstIP, ip6.SrcIP, ip6.NextHeader, uint16(tcp.DstPort), uint16(tcp.SrcPort))
			} else if translayer.LayerType() == layers.LayerTypeUDP {
				udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
				flow = createFlowIPTCPUDP(6, ip6.DstIP, ip6.SrcIP, ip6.NextHeader, uint16(udp.DstPort), uint16(udp.SrcPort))
			} else {
				flow = createFlowIP(6, ip6.DstIP, ip6.SrcIP, ip6.NextHeader)
			}
		}
	} else {
		panic("trace packet is non-ip")
	}

	// return flow instance
	return flow
}

// Key returns a string key for flow, which can be used as a key to a map.
func (flow Flow) Key() string {
	if flow.ip == nil {
		panic("flow does not have an IP header")
	}

	var key string

	if flow.l4 != nil {
		key = fmt.Sprintf("%d-%s-%s-%d-%d-%d", flow.ip.version, flow.ip.daddr,
			flow.ip.saddr, uint8(flow.ip.proto), flow.l4.dport, flow.l4.sport)
	} else {
		key = fmt.Sprintf("%d-%s-%s-%d", flow.ip.version, flow.ip.daddr,
			flow.ip.saddr, uint8(flow.ip.proto))
	}

	return key
}

// createFlowIP creates an IP flow.
func createFlowIP(version int, daddr, saddr net.IP, proto layers.IPProtocol) *Flow {
	if version != 4 && version != 6 {
		panic("invalid ip version")
	}

	return &Flow{
		ip: &FlowIP{
			version: version,
			daddr:   daddr,
			saddr:   saddr,
			proto:   proto,
		},
		l4: nil,
	}
}

// createFlowIPTCPUDP creates an IP flow, which contains a TCP/UDP payload.
func createFlowIPTCPUDP(version int, daddr, saddr net.IP, proto layers.IPProtocol, dport, sport uint16) *Flow {
	if proto != layers.IPProtocolTCP && proto != layers.IPProtocolUDP {
		panic("invalid l4 protocol")
	}

	flow := createFlowIP(version, daddr, saddr, proto)
	flow.l4 = &FlowL4{
		dport: dport,
		sport: sport,
	}
	return flow
}
