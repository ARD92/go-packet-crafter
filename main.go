/* Packet crafter based on gopacket
Author: Aravind Prabhakar
Version: 1.0
Description: simple go based packet generator for testing flows/firewall filters for vNF/cNFs. It can also
             be used to craft packets for other testing purposes. This is not intended to test performance.
*/

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akamensky/argparse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/* Variable declarations */
var (
	str      string
	sipaddr  []byte
	dipaddr  []byte
	protocol layers.IPProtocol
	mpls     *layers.MPLS
	payload  gopacket.SerializableLayer
	buffer   gopacket.SerializeBuffer
	icmp     *layers.ICMPv4
	icmp6    *layers.ICMPv6
	iecho    *layers.ICMPv6Echo
	tcp      *layers.TCP
	udp      *layers.UDP
	smac     []byte
	dmac     []byte
	eth      *layers.Ethernet
	pkt      []byte
	pktarray [][]byte
)

/*
	Struct to parse IPv4 ranges

This will store if there is a single range or a range
if octet is single value then [value] would be stored.
if octet is a range then [startValue endValue] would be stored
*/
type OctetsIpv4 struct {
	octet1 []string
	octet2 []string
	octet3 []string
	octet4 []string
}

/*
	Parse IPv4 address in case a range is provided.

the range of octet is split by -
example: 1-10.1-5.2-5.10-30
will return 4 octets. [1-10],[1-5],[2-5],[10-30] into struct OctetsIpv4
further it will create a list of all the combinations of Ipaddresses.
[1.1.2.10,1.1.2.11,.....10.5.5.30]
*/
func parseIpv4Range(ipv4address string) []string {
	var octipv4 OctetsIpv4
	var iplist []string
	asplit := strings.Split(ipv4address, ".")
	for i := 0; i <= len(asplit)-1; i++ {
		if strings.Contains(asplit[i], "-") {
			ip := strings.Split(asplit[i], "-")
			switch i {
			case 0:
				octipv4.octet1 = ip
			case 1:
				octipv4.octet2 = ip
			case 2:
				octipv4.octet3 = ip
			case 3:
				octipv4.octet4 = ip
			}
		} else {
			switch i {
			case 0:
				octipv4.octet1 = []string{asplit[i]}
			case 1:
				octipv4.octet2 = []string{asplit[i]}
			case 2:
				octipv4.octet3 = []string{asplit[i]}
			case 3:
				octipv4.octet4 = []string{asplit[i]}
			}
		}
	}
	if len(octipv4.octet1) != 1 {
		starti, _ := strconv.Atoi(octipv4.octet1[0])
		endi, _ := strconv.Atoi(octipv4.octet1[1])
		for i := starti; i <= endi; i++ {
			map1 := strconv.Itoa(i)
			if len(octipv4.octet2) != 1 {
				startj, _ := strconv.Atoi(octipv4.octet2[0])
				endj, _ := strconv.Atoi(octipv4.octet2[1])
				for j := startj; j <= endj; j++ {
					map2 := strconv.Itoa(j)
					if len(octipv4.octet3) != 1 {
						startk, _ := strconv.Atoi(octipv4.octet3[0])
						endk, _ := strconv.Atoi(octipv4.octet3[1])
						for k := startk; k <= endk; k++ {
							map3 := strconv.Itoa(k)
							if len(octipv4.octet4) != 1 {
								startl, _ := strconv.Atoi(octipv4.octet4[0])
								endl, _ := strconv.Atoi(octipv4.octet4[1])
								for l := startl; l <= endl; l++ {
									map4 := strconv.Itoa(l)
									iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
								}
							} else {
								map4 := octipv4.octet4[0]
								iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
							}
						}
					} else {
						map3 := octipv4.octet3[0]
						if len(octipv4.octet4) != 1 {
							startl, _ := strconv.Atoi(octipv4.octet4[0])
							endl, _ := strconv.Atoi(octipv4.octet4[1])
							for l := startl; l <= endl; l++ {
								map4 := strconv.Itoa(l)
								iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
							}
						} else {
							map4 := octipv4.octet4[0]
							iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
						}
					}
				}
			} else {
				map2 := octipv4.octet2[0]
				if len(octipv4.octet3) != 1 {
					startk, _ := strconv.Atoi(octipv4.octet3[0])
					endk, _ := strconv.Atoi(octipv4.octet3[1])
					for k := startk; k <= endk; k++ {
						map3 := strconv.Itoa(k)
						if len(octipv4.octet4) != 1 {
							startl, _ := strconv.Atoi(octipv4.octet4[0])
							endl, _ := strconv.Atoi(octipv4.octet4[1])
							for l := startl; l <= endl; l++ {
								map4 := strconv.Itoa(l)
								iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
							}
						} else {
							map4 := octipv4.octet4[0]
							iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
						}
					}
				} else {
					map3 := octipv4.octet3[0]
					if len(octipv4.octet4) != 1 {
						startl, _ := strconv.Atoi(octipv4.octet4[0])
						endl, _ := strconv.Atoi(octipv4.octet4[1])
						for l := startl; l <= endl; l++ {
							map4 := strconv.Itoa(l)
							iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
						}
					} else {
						map4 := octipv4.octet4[0]
						iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
					}
				}
			}
		}
	} else {
		map1 := octipv4.octet1[0]
		if len(octipv4.octet2) != 1 {
			startj, _ := strconv.Atoi(octipv4.octet2[0])
			endj, _ := strconv.Atoi(octipv4.octet2[1])
			for j := startj; j <= endj; j++ {
				map2 := strconv.Itoa(j)
				if len(octipv4.octet3) != 1 {
					startk, _ := strconv.Atoi(octipv4.octet3[0])
					endk, _ := strconv.Atoi(octipv4.octet3[1])
					for k := startk; k <= endk; k++ {
						map3 := strconv.Itoa(k)
						if len(octipv4.octet4) != 1 {
							startl, _ := strconv.Atoi(octipv4.octet4[0])
							endl, _ := strconv.Atoi(octipv4.octet4[1])
							for l := startl; l <= endl; l++ {
								map4 := strconv.Itoa(l)
								iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
							}
						} else {
							map4 := octipv4.octet4[0]
							iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
						}
					}
				} else {
					map3 := octipv4.octet3[0]
					if len(octipv4.octet4) != 1 {
						startl, _ := strconv.Atoi(octipv4.octet4[0])
						endl, _ := strconv.Atoi(octipv4.octet4[1])
						for l := startl; l <= endl; l++ {
							map4 := strconv.Itoa(l)
							iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
						}
					} else {
						map4 := octipv4.octet4[0]
						iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
					}
				}
			}
		} else {
			map2 := octipv4.octet2[0]
			if len(octipv4.octet3) != 1 {
				startk, _ := strconv.Atoi(octipv4.octet3[0])
				endk, _ := strconv.Atoi(octipv4.octet3[1])
				for k := startk; k <= endk; k++ {
					map3 := strconv.Itoa(k)
					if len(octipv4.octet4) != 1 {
						startl, _ := strconv.Atoi(octipv4.octet4[0])
						endl, _ := strconv.Atoi(octipv4.octet4[1])
						for l := startl; l <= endl; l++ {
							map4 := strconv.Itoa(l)
							iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
						}
					} else {
						map4 := octipv4.octet4[0]
						iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
					}
				}
			} else {
				map3 := octipv4.octet3[0]
				if len(octipv4.octet4) != 1 {
					startl, _ := strconv.Atoi(octipv4.octet4[0])
					endl, _ := strconv.Atoi(octipv4.octet4[1])
					for l := startl; l <= endl; l++ {
						map4 := strconv.Itoa(l)
						iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
					}
				} else {
					map4 := octipv4.octet4[0]
					iplist = append(iplist, map1+"."+map2+"."+map3+"."+map4)
				}
			}
		}
	}
	return iplist
}

/* Function to create MPLS layer */
func Mpls(label uint32, stack bool) *layers.MPLS {
	mpls := &layers.MPLS{
		Label:        label,
		TrafficClass: 0,
		StackBottom:  stack,
		TTL:          64,
	}
	return mpls
}

/*
	Funciton to create GTP header

if sequence number is used, then the internal TCP/UDP packet may
not get decoded as expected on wireshark if the sequence numbers
do not add up. Call the function accordingly when using the tool
By default it is marked as false. By doing so a GTP packet with TPDU
session would look like
ETH <--IP<-- UDP(2152)<--GTP<--IP<--TCP/UDP<--payload
*/
func Gtp(version uint8, teid uint32, msgtype uint8, msglength uint16) *layers.GTPv1U {
	gtp := &layers.GTPv1U{
		Version:             1,
		ProtocolType:        1,
		Reserved:            0,
		ExtensionHeaderFlag: false,
		SequenceNumberFlag:  false,
		NPDUFlag:            false,
		MessageType:         msgtype,
		MessageLength:       msglength,
		TEID:                teid,
		//SequenceNumber: 0x28db,
		//NPDU:
	}
	return gtp
}

/* Function to create VXLAN header */
func Vxlan(vni uint32, validflag bool) *layers.VXLAN {
	vxlan := &layers.VXLAN{
		ValidIDFlag: validflag,
		VNI:         vni,
		//GBPExtension:
		//GBPDontLearn:
		//GBPApplied:
		//GBPGroupPolicyID:
	}
	return vxlan
}

/* Hexstring to Byte conversion */
func HexToByte(HexPkt string) []byte {
	hexpkt, err := hex.DecodeString(HexPkt)
	if err != nil {
		panic(err)
	}
	return hexpkt
}

/*
Create IPv6 packet .variables in order

sourceips[s], destips[d], *ptype, *sport, *dport, *payload, *smac, *dmac
*/
func createV6Packet(variables ...string) []byte {
	if len(variables[0]) != 0 {
		sipaddr = net.ParseIP(variables[0])
		if sipaddr == nil {
			panic("Not a valid IPv6 source address")
		}

	} else {
		panic("source IPv6 missing")
	}
	if len(variables[1]) != 0 {
		dipaddr = net.ParseIP(variables[1])
		if dipaddr == nil {
			panic("Not a valid Ipv6 destination address")
		}
	} else {
		panic("destination IPv6 missing \n")
	}
	if len(variables[2]) != 0 {
		if variables[2] == "icmp6" {
			icmp6 = &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
			iecho = &layers.ICMPv6Echo{Identifier: 35859, SeqNumber: 1}
		} else if variables[2] == "udp" {
			if len(variables[3]) != 0 && len(variables[4]) != 0 {
				source, _ := strconv.Atoi(variables[3])
				dest, _ := strconv.Atoi(variables[4])
				udp = &layers.UDP{SrcPort: layers.UDPPort(source), DstPort: layers.UDPPort(dest)}
				protocol = layers.IPProtocolUDP
			} else {
				panic("source port and destination port missing. please add accordingly\n")
			}
		}
	}
	// payload [5]
	if len(variables[5]) != 0 {
		payload = gopacket.Payload(variables[6])
	} else {
		payload = gopacket.Payload("gopayload")
	}

	// smac[6]
	if len(variables[6]) != 0 {
		smac, _ = net.ParseMAC(variables[6])
	} else {
		smac, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
		fmt.Println("using broadcast address for Source MAC")
	}

	// dmac[7]
	if len(variables[7]) != 0 {
		dmac, _ = net.ParseMAC(variables[7])
	} else {
		dmac, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
		fmt.Println("using broadcast address for Dest MAC")
	}

	if variables[2] == "udp" {
		fmt.Println(" --> IP packet with udp \n")
		eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x086DD}
		ip := &layers.IPv6{Version: 6, DstIP: dipaddr, SrcIP: sipaddr, NextHeader: layers.IPProtocolUDP, HopLimit: 64}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil
		}
		buffer = gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
			eth, ip, udp, payload); err != nil {
			return nil
		}
	} else if variables[2] == "icmp6" {
		fmt.Println(" --> IP packet with icmp6 \n")
		eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x086DD}
		ip := &layers.IPv6{Version: 6, DstIP: dipaddr, SrcIP: sipaddr, NextHeader: layers.IPProtocolICMPv6, HopLimit: 64}
		if err := icmp6.SetNetworkLayerForChecksum(ip); err != nil {
			return nil
		}
		buffer = gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
			eth, ip, icmp6, iecho, payload); err != nil {
			return nil
		}
	}
	return buffer.Bytes()
}

/*
Function to create the packet to be sent

on wire. This would be called based on the
inputs passed with the arguments
*/
func createPacket(variables ...string) []byte {
	// variable declaration
	var (
		mplsarray []*layers.MPLS
		vxlan     *layers.VXLAN
		gtp       *layers.GTPv1U

		// Inner packet variables
		ieth        *layers.Ethernet
		iip         *layers.IPv4
		itcp        *layers.TCP
		iudp        *layers.UDP
		iicmp       *layers.ICMPv4
		innerlength int64
	)

	// Begin parsing
	// sourceIP [0]
	if len(variables[0]) != 0 {
		sipaddr = net.ParseIP(variables[0])
	} else {
		panic("source IP missing\n")
	}
	// destinationIp [1]
	if len(variables[1]) != 0 {
		dipaddr = net.ParseIP(variables[1])
	} else {
		panic("destination IP missing \n")
	}
	// type [2] icmp, tcp or udp
	if len(variables[2]) != 0 {
		if variables[2] == "icmp" {
			icmp = &layers.ICMPv4{TypeCode: layers.ICMPv4TypeCode(uint16(8) << 8), Id: 1, Seq: 1}
			protocol = layers.IPProtocolICMPv4
		} else if variables[2] == "udp" {
			if len(variables[3]) != 0 && len(variables[4]) != 0 {
				source, _ := strconv.Atoi(variables[3])
				dest, _ := strconv.Atoi(variables[4])
				udp = &layers.UDP{SrcPort: layers.UDPPort(source), DstPort: layers.UDPPort(dest)}
				protocol = layers.IPProtocolUDP
			} else {
				panic("source port and destination port missing. please add accordingly\n")
			}
		} else if variables[2] == "tcp" {
			if len(variables[3]) != 0 && len(variables[4]) != 0 {
				source, _ := strconv.Atoi(variables[3])
				dest, _ := strconv.Atoi(variables[4])
				tcp = &layers.TCP{SrcPort: layers.TCPPort(source), DstPort: layers.TCPPort(dest),
					SYN: true}
				protocol = layers.IPProtocolTCP
			} else {
				panic("source port and/or destination port missing. Please add accordingly\n")
			}
		}
	} else {
		fmt.Print("type parameter is missing \n")
	}

	// optional params begin here onwards
	// mpls [5]
	if len(variables[5]) != 0 {
		if strings.Contains(variables[5], ",") {
			resultm := strings.Split(variables[5], ",")
			for i := 0; i <= len(resultm)-1; i++ {
				val, _ := strconv.Atoi(resultm[i])
				if i == 0 {
					// mpls bottom of stack
					mpls = Mpls(uint32(val), true)
				} else {
					// mpls not bottom of stack
					mpls = Mpls(uint32(val), false)
				}
				mplsarray = append(mplsarray, mpls)
			}
		} else {
			// single label handling
			val, _ := strconv.Atoi(variables[5])
			mpls = Mpls(uint32(val), true)
			mplsarray = append(mplsarray, mpls)
		}
	}

	// payload [6]
	if len(variables[6]) != 0 {
		payload = gopacket.Payload(variables[6])
	} else {
		payload = gopacket.Payload("gopayload")
	}

	// smac[7]
	if len(variables[7]) != 0 {
		smac, _ = net.ParseMAC(variables[7])
	} else {
		smac, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
		fmt.Println("using broadcast address for Source MAC")
	}

	// dmac[8]
	if len(variables[8]) != 0 {
		dmac, _ = net.ParseMAC(variables[8])
	} else {
		dmac, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
		fmt.Println("using broadcast address for Dest MAC")
	}

	//vxlan[9]
	/* Vxlan(vni) */
	if len(variables[9]) != 0 {
		val, _ := strconv.Atoi(variables[9])
		// if vlan id then true
		vxlan = Vxlan(uint32(val), true)
	}

	/*innerhex[10]
	  Handles the inner packet when defined as hex string as part
	  of argument -x/--inhex . This will decode the layers accordingly
	  and add to the buffer to craft the packet. Necessary TCP/UDP/IP/ETH
	  layers are decoded. This will be used when crafting packets which are
	  encapsulated such as vxlan, gtp, gre
	*/
	if len(variables[10]) != 0 {
		hexb := HexToByte(variables[10])
		npkt := gopacket.NewPacket(hexb, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Println("--> Inner packet payload received")
		buffer = gopacket.NewSerializeBuffer()

		// Decode payload
		applicationLayer := npkt.ApplicationLayer()
		if applicationLayer != nil {
			ipayload := gopacket.Payload(applicationLayer.Payload())
			fmt.Printf("|-> Inner payload: %s\n", applicationLayer.Payload())
			if err := ipayload.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				return nil
			}
		}
		// Decode IP layer
		ipLayer := npkt.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			iip, _ = ipLayer.(*layers.IPv4)
		}
		fmt.Printf("|-> Inner Source IP: %s Inner Dest IP: %s \n", iip.SrcIP, iip.DstIP)
		// Decode ICMP layer
		icmpLayer := npkt.Layer(layers.LayerTypeICMPv4)
		if icmpLayer != nil {
			iicmp, _ = icmpLayer.(*layers.ICMPv4)
			fmt.Printf("|-> Inner pkt ICMP received \n")
			if err := iicmp.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				return nil
			}
		}
		// Decode UDP layer
		udpLayer := npkt.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			iudp, _ = udpLayer.(*layers.UDP)
			if err := iudp.SetNetworkLayerForChecksum(iip); err != nil {
				return nil
			}
			if err := iudp.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				return nil
			}
			fmt.Printf("|-> Inner UDP source port: %s Dest port: %s\n", iudp.SrcPort, iudp.DstPort)
		}
		// Decode TCP layer
		tcpLayer := npkt.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			itcp, _ = tcpLayer.(*layers.TCP)
			if err := itcp.SetNetworkLayerForChecksum(iip); err != nil {
				return nil
			}
			if err := itcp.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				return nil
			}
			fmt.Printf("|-> Inner TCP source port: %s Dest port %s \n", itcp.SrcPort, itcp.DstPort)
		}

		if err := iip.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		// Decode IP layer
		ethLayer := npkt.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			ieth, _ = ethLayer.(*layers.Ethernet)
			// For GTP Eth layer should be stripped off. Else packet will be malformed. Only L3 and above gets tunneled
			// For L2 tunneling such as VXLAN (var9), eth layer should get added
			if len(variables[9]) != 0 {
				if err := ieth.SerializeTo(buffer,
					gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
					panic(err)
				}
				fmt.Printf("|-> Inner MAC source mac: %s, Dest Mac %s \n", ieth.SrcMAC, ieth.DstMAC)
			}
		}
		innerlength = int64(len(buffer.Bytes()))
		fmt.Printf("|-> Length: %d \n", innerlength)
	}

	// GTP[11]
	/* Gtp(version, teid, msgtype, msglength) */
	if len(variables[11]) != 0 {
		val, _ := strconv.Atoi(variables[11])
		gtp = Gtp(uint8(1), uint32(val), uint8(0xff), uint16(innerlength))
	}

	// create Packet
	/*
	   if UDP: eth, ip, udp, payload
	   if TCP: eth, ip, tcp, payload
	   if icmp: eth, ip, icmp
	   if mpls: eth, mpls, ip, udp/tcp, payload
	   if dual mpls stacked: eth, mpls, mpls, ip, udp, payload
	   if gre: eth, ip, gre, inner ip
	   if vxlan: eth, ip, udp (dport 4789), vxlan, eth, ip, udp, payload
	*/

	// mpls and udp
	if len(variables[5]) != 0 && variables[2] == "udp" {
		fmt.Println(" --> MPLS packet with udp transport \n")
		eth = &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x8847}
		ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol, TTL: 64}
		if len(variables[10]) == 0 {
			buffer = gopacket.NewSerializeBuffer()
			if err := payload.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				panic(err)
			}
		}
		if err := payload.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil
		}
		if err := udp.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := ip.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		// Handle stack of mpls labels
		for final := 0; final <= len(mplsarray)-1; final++ {
			mpl := mplsarray[final]
			if err := mpl.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				return nil
			}
		}
		if err := eth.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			return nil
		}
		// mpls and tcp
	} else if len(variables[5]) != 0 && variables[2] == "tcp" {
		fmt.Println(" --> MPLS packet with TCP \n")
		eth = &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x8847}
		ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol, TTL: 64}
		if len(variables[10]) == 0 {
			buffer = gopacket.NewSerializeBuffer()
			if err := payload.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				panic(err)
			}
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil
		}
		if err := tcp.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := ip.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		// Handle stack of mpls labels
		for final := 0; final <= len(mplsarray)-1; final++ {
			mpl := mplsarray[final]
			if err := mpl.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				return nil
			}
		}
		if err := eth.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			return nil
		}
		// no mpls and udp
	} else if len(variables[5]) == 0 && variables[2] == "udp" && len(variables[9]) == 0 && len(variables[11]) == 0 {
		fmt.Println(" --> IP packet with udp \n")
		eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
		ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol, TTL: 64}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil
		}
		buffer = gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
			eth, ip, udp, payload); err != nil {
			return nil
		}
		// no mpls and tcp
	} else if len(variables[5]) == 0 && variables[2] == "tcp" {
		fmt.Println(" --> IP packet with TCP ports \n")
		eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
		ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol, TTL: 64}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil
		}
		buffer = gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
			eth, ip, tcp, payload); err != nil {
			return nil
		}
		// icmp
	} else if variables[2] == "icmp" {
		fmt.Println(" --> ICMP packet \n")
		eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
		ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol, TTL: 64}
		buffer = gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
			eth, ip, icmp, payload); err != nil {
			return nil
		}
		// Vxlan . Ensure destination UDP port is 4789
	} else if len(variables[9]) != 0 && variables[2] == "udp" {
		fmt.Println("\n--> VXLAN Packet")
		fmt.Printf("|-> VNI:  %s\n", variables[9])
		eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
		ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol, TTL: 64}
		if len(variables[10]) == 0 {
			buffer = gopacket.NewSerializeBuffer()
			if err := payload.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				panic(err)
			}
		}
		if err := vxlan.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil
		}
		if err := udp.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := ip.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := eth.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			return nil
		}
		// GTP-U v1 packet. Ensure the destination UDP port is 2152
	} else if len(variables[11]) != 0 && variables[2] == "udp" && len(variables[9]) == 0 {
		fmt.Printf("\n--> GTP Packet \n")
		fmt.Printf("|-> TEID: %s \n", variables[11])
		eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
		ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol, TTL: 64}
		if len(variables[10]) == 0 {
			buffer = gopacket.NewSerializeBuffer()
			if err := payload.SerializeTo(buffer,
				gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
				panic(err)
			}
		}
		if err := gtp.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			return nil
		}
		if err := udp.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := ip.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			panic(err)
		}
		if err := eth.SerializeTo(buffer,
			gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}); err != nil {
			return nil
		}
	}
	return buffer.Bytes()
}

//save to pcap
/*func PcapCreate(name string, pkt []byte) {
    var snapshot_len uint32  = 65535
    file,err := os.Create(name+".pcap")
    if err != nil {
        panic("unable to open file")
    }
    defer file.Close()
    pkgsrc := gopacket.NewPacketSource(pkt, layers.LayerTypeEthernet)
    pcapw := pcapgo.NewWriter(file)
    pcapw.WriteFileHeader(snapshot_len, layers.LinkTypeEthernet)
    pcapw.WritePacket(pkgsrc.CaptureInfo(), pkt)
}*/

/*Send crafted packets over wire */
func PacketSend(device string, packet []byte, promiscuous bool) {
	var snapshot_len int32 = 65535
	//var promiscuous bool = false
	var timeout = 30 * time.Second
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Send raw bytes over wire
	err = handle.WritePacketData(packet)
	if err != nil {
		panic(err)
	}
}

/* Print hex string of the newly crafted packet */
func PrintHex(packet []byte) {
	str = hex.EncodeToString(buffer.Bytes())
	if len(str) != 0 {
		fmt.Println("\n============= Hex packet crafted ===========\n")
		fmt.Printf(str)
		fmt.Println("\n=================================================\n")
	}
}

/* Create banner for the tool */
func Banner() {
	const banner = `
                      ____         ____            _        _      ____            __ _
                     / ___| ___   |  _ \ __ _  ___| | _____| |_   / ___|_ __ __ _ / _| |_ ___ _ __
                    | |  _ / _ \  | |_) / _ |/ __| |/ / _ \ __| | |   |  __/ _ | |_| __/ _ \  __|
                    | |_| | (_) | |  __/ (_| | (__|   <  __/ |_  | |___| | | (_| |  _| ||  __/ |
                     \____|\___/  |_|   \__,_|\___|_|\_\___|\__|  \____|_|  \__,_|_|  \__\___|_| 
                    `
	fmt.Println(banner)
}

/* Main function */
func main() {
	Banner()
	//Argparser
	parser := argparse.NewParser("Required-args", "\n=================\ngo packet crafter\n=================")
	sip := parser.String("S", "sip", &argparse.Options{Required: true, Help: "Source Ip address to use as outer IP header"})
	dip := parser.String("D", "dip", &argparse.Options{Required: true, Help: "Destination IP address to use as outer IP header"})
	sport := parser.String("s", "sport", &argparse.Options{Required: false, Help: "Source Port in outer IP header. Can be single integer or a range 1000-2000"})
	dport := parser.String("d", "dport", &argparse.Options{Required: false, Help: "Destination Port in outer IP header. Can be single integer or a range 1000-2000"})
	ptype := parser.String("t", "type", &argparse.Options{Required: true, Help: "Type of packet. Can be tcp, udp, icmp, icmp6. if icmp(6) then dont mention source and dest ports."})
	mpls := parser.String("l", "mpls", &argparse.Options{Required: false, Help: "Mpls labels. Can be single integer or a label stack such as 1000,2000,3000 . In this case the first label would be bottom of the stack"})
	payload := parser.String("p", "payload", &argparse.Options{Required: false, Help: "optional payload string. if not provided, will use 'payload' as the payload in the packet"})
	smac := parser.String("m", "smac", &argparse.Options{Required: false, Help: "source MAC address"})
	dmac := parser.String("M", "dmac", &argparse.Options{Required: false, Help: "destination MAC address"})
	vxlan := parser.String("v", "vni", &argparse.Options{Required: false, Help: "vxlan vni id"})
	inhex := parser.String("x", "inpkt", &argparse.Options{Required: false, Help: "Inner packet in hex format which can be used"})
	teid := parser.String("T", "teid", &argparse.Options{Required: false, Help: "TEID of GTPv1u packet. For the inner packet which is tunneld, use inhex vals"})
	//pcap := parser.String("w", "write", &argparse.Options{Required: false, Help: "Write the crafted packet to pcap file"})
	intf := parser.String("i", "interface", &argparse.Options{Required: false, Help: "Interface over which we need to send the created packets"})
	promiscuous := parser.String("P", "promiscuous", &argparse.Options{Required: false, Help: "Optioinal param to enable Promiscuous mode for the interface which is a boolean value. use true to enable and false to disable. default is false if not mentioned"})
	hex := parser.String("H", "hexprint", &argparse.Options{Required: false, Help: "Optional param to print HEX data of the created packet. you can then use any decoder like wireshark or online tools"})
	numpkts := parser.String("n", "numpkt", &argparse.Options{Required: false, Help: "Number of packets to send over wire"})
	pip := parser.String("I", "iptype", &argparse.Options{Required: false, Help: "IP type. ipv4 or ipv6"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	} else {
		/*
		   Pass the below arguments to craft the packet
		   Arglist in order: [Sourceip, DestinationIp, Type, Sourceport, Destinationport, mpls, payload, pcap]
		*/
		if strings.Contains(*sport, "-") && strings.Contains(*dport, "-") {
			result := strings.Split(*sport, "-")
			result1 := strings.Split(*dport, "-")
			starts, _ := strconv.Atoi(result[0])
			ends, _ := strconv.Atoi(result[1])
			startd, _ := strconv.Atoi(result1[0])
			endd, _ := strconv.Atoi(result1[1])
			sourceips := parseIpv4Range(*sip)
			destips := parseIpv4Range(*dip)
			for s := 0; s <= len(sourceips)-1; s++ {
				for d := 0; d <= len(destips)-1; d++ {
					for i := starts; i <= ends; i++ {
						for j := startd; j <= endd; j++ {
							pkt = createPacket(sourceips[s], destips[d], *ptype, strconv.Itoa(i), strconv.Itoa(j), *mpls, *payload, *smac, *dmac, *vxlan, *inhex, *teid)
							pktarray = append(pktarray, pkt)
						}
					}
				}
			}
		} else if strings.Contains(*sport, "-") && !strings.Contains(*dport, "-") {
			result := strings.Split(*sport, "-")
			starts, _ := strconv.Atoi(result[0])
			ends, _ := strconv.Atoi(result[1])
			sourceips := parseIpv4Range(*sip)
			destips := parseIpv4Range(*dip)
			for s := 0; s <= len(sourceips)-1; s++ {
				for d := 0; d <= len(destips)-1; d++ {
					for i := starts; i <= ends; i++ {
						pkt = createPacket(sourceips[s], destips[d], *ptype, strconv.Itoa(i), *dport, *mpls, *payload, *smac, *dmac, *vxlan, *inhex, *teid)
						pktarray = append(pktarray, pkt)
					}
				}
			}
		} else if !strings.Contains(*sport, "-") && strings.Contains(*dport, "-") {
			result1 := strings.Split(*dport, "-")
			startd, _ := strconv.Atoi(result1[0])
			endd, _ := strconv.Atoi(result1[1])
			sourceips := parseIpv4Range(*sip)
			destips := parseIpv4Range(*dip)
			for s := 0; s <= len(sourceips)-1; s++ {
				for d := 0; d <= len(destips)-1; d++ {
					for j := startd; j <= endd; j++ {
						pkt = createPacket(sourceips[s], destips[d], *ptype, *sport, strconv.Itoa(j), *mpls, *payload, *smac, *dmac, *vxlan, *inhex, *teid)
						pktarray = append(pktarray, pkt)
					}
				}
			}
		} else if *pip == "ipv6" {
			fmt.Println("generating IPv6 packet.. ")
			pkt = createV6Packet(*sip, *dip, *ptype, *sport, *dport, *payload, *smac, *dmac)
			pktarray = append(pktarray, pkt)
		} else {
			sourceips := parseIpv4Range(*sip)
			destips := parseIpv4Range(*dip)
			for s := 0; s <= len(sourceips)-1; s++ {
				for d := 0; d <= len(destips)-1; d++ {
					pkt = createPacket(sourceips[s], destips[d], *ptype, *sport, *dport, *mpls, *payload, *smac, *dmac, *vxlan, *inhex, *teid)
					pktarray = append(pktarray, pkt)
				}
			}
		}

		//if pcap != nil {
		//    fmt.Println("\n======= Storing into pcap file ===========\n")
		//    PcapCreate(*pcap, pkt)
		//}

		// send packets over interface
		if len(*intf) != 0 {
			if *promiscuous == "true" {
				fmt.Println("\n--> Sending packet in promiscuous mode.. \n ")
				numpkt, _ := strconv.Atoi(*numpkts)
				interval := float64(1.0) / float64(numpkt)
				start := 0.0
				end := 1.0
				for i := start; i < end; i += interval {
					if len(pktarray) != 0 {
						for p := 0; p <= len(pktarray)-1; p++ {
							PacketSend(*intf, pktarray[p], true)
							if len(*hex) != 0 && *hex == "true" {
								PrintHex(pktarray[p])
							}
						}
					} else {
						PacketSend(*intf, pkt, true)
						if len(*hex) != 0 && *hex == "true" {
							PrintHex(pkt)
						}
					}
				}
			} else {
				fmt.Println("\n--> Sending packet.. ")
				numpkt, _ := strconv.Atoi(*numpkts)
				interval := float64(1.0) / float64(numpkt)
				start := 0.0
				end := 1.0
				for i := start; i <= end; i += interval {
					if len(pktarray) != 0 {
						for p := 0; p <= len(pktarray)-1; p++ {
							PacketSend(*intf, pktarray[p], false)
							if len(*hex) != 0 && *hex == "true" {
								PrintHex(pktarray[p])
							}
						}
					} else {
						PacketSend(*intf, pkt, false)
						if len(*hex) != 0 && *hex == "true" {
							PrintHex(pkt)
						}
					}
				}
			}
		}
	}
}
