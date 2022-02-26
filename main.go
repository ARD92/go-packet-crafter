/* Packet crafter based on gopacket 
Author: Aravind Prabhakar
Version: 1.0
Description: simple go based packet generator for testing flows/firewall filters for vNFs. It can also
             be used to craft packets for other testing purposes. This is not to test performance which 
             can be enhanced later. 


Caveats:
1. only single label can be used. Multiple label stack is not supported
2. only single port can be used. Range of ports is not supported
3. write to pcap is not yet supported
4. vlanids, GTP, VXLAN and GRE headers not yet supported
5. Does not support IPv6

Usage: ./go-packet-gen -src <IP> -dst <IP> -t <tcp/udp> -sport <port/[port-port]> -dport <port/[port-port]>
       ./go-packet-gen -src <IP> -dst <IP> -t icmp 
       ./go-packet-gen -src <IP> -dst <IP> -t <tcp/udp> -l <label/[label1 label2 label3]> -sport <port> -dport <port> -m <sourcemac> -M <destMAC> -p "test123" -w test.pcap

Documentation: gopacket documentation exists @ https://pkg.go.dev/github.com/google/gopacket@v1.1.19/layers#TCP
*/


package main

import (
    "fmt"
    "net"
    "encoding/hex"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    //"github.com/google/gopacket/pcapgo"
    "github.com/akamensky/argparse"
    "os"
    "strconv"
    "time"
    )


var str string
var sipaddr []byte
var dipaddr []byte
var protocol layers.IPProtocol
var mpls *layers.MPLS
var payload gopacket.SerializableLayer
var buffer gopacket.SerializeBuffer
var icmp *layers.ICMPv4
var tcp *layers.TCP
var udp *layers.UDP
var smac []byte
var dmac []byte
var eth *layers.Ethernet 

/* Function to create MPLS layer */
func Mpls (label uint32, stack bool) *layers.MPLS {
    mpls:= &layers.MPLS {
        Label: label,
        TrafficClass: 0,
        StackBottom: stack,
        TTL: 64,
    }
    return mpls
}

/*
func Gtp() {
    gtp := &layers.GTPv1U {
        Version: 
        ProtocolType:
        Reserved: 
        ExtensionHeaderFlag:
        SequenceNumberFlag:
        NPDUFlag:
        MessageType:
        MessageLength:
        TEID:
        SequenceNumber:
        NPDU:
        GTPExtensionHeaders: 
    }
}

func Tcp() {
    tcp := &layers.TCP {
        SrcPort, DstPort 
        Seq
        Ack
        DataOffset
        FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
        Window
        Checksum
        urgent
    }
        
}

func Vxlan(){
    vxlan := &layers.VXLAN {
        ValidIDFlag: 
        VNI:
        GBPExtension:
        GBPDontLearn:
        GBPApplied:
        GBPGroupPolicyID:
    }
}
*/

func createPacket(variables ...string) []byte {
    // variable declaration 
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
            icmp = &layers.ICMPv4{TypeCode: layers.ICMPv4TypeCode(8), Id: 1, Seq: 1}
            //protocol = layers.IPProtocolICMPv4 // fix this!!
        } else if variables[2] == "udp" {
            if len(variables[3]) != 0 && len(variables[4]) != 0 {
                source,_ := strconv.Atoi(variables[3])
                dest,_ := strconv.Atoi(variables[4])
                udp = &layers.UDP{SrcPort: layers.UDPPort(source), DstPort: layers.UDPPort(dest)}
                protocol = layers.IPProtocolUDP
            } else {
                panic("source port and destination port missing. please add accordingly\n")
            }
        } else if variables[2] == "tcp" {
            if len(variables[3]) != 0 && len(variables[4]) != 0 {
                source,_ := strconv.Atoi(variables[3])
                dest,_ := strconv.Atoi(variables[4])
                tcp = &layers.TCP{SrcPort: layers.TCPPort(source), DstPort: layers.TCPPort(dest),
                SYN: true }
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
        val,_ := strconv.Atoi(variables[5])
        mpls = Mpls(uint32(val), true)
    } 
    // payload [6]
    if len(variables[6]) != 0 {
        payload = gopacket.Payload(variables[6])
    } else {
        payload = gopacket.Payload("gopayload")
    }
    
    // smac[7]
    if len(variables[7]) != 0 {
        smac,_ = net.ParseMAC(variables[7])
    } else {
        smac,_ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
        fmt.Println("using broadcast address for MAC")
    }

    // dmac[8]
    if len(variables[8]) != 0 {
        dmac,_ = net.ParseMAC(variables[8])
    } else {
        dmac,_ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
        fmt.Println("using broadcast address for MAC")
    }


    // create Packet
    /* 
    if UDP: eth, ip, udp, payload
    if TCP: eth, ip, tcp, payload
    if icmp: eth, ip, icmp
    if mpls: eth, mpls, ip, udp/tcp, payload
    if dual mpls stacked: eth, mpls, mpls, ip, udp, payload
    if gre: eth, ip, gre, inner ip
    if vxlan: 
    */ 

    // mpls and udp
    if len(variables[5]) != 0 && variables[2] == "udp" {
        eth = &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x8847}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        fmt.Println(ip)
        if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
            return nil
        }
        buffer = gopacket.NewSerializeBuffer()
        if err := gopacket.SerializeLayers(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true },
            eth, mpls, ip, udp, payload); err != nil {
            return nil
            }
    // mpls and tcp
    } else if len(variables[5]) != 0 && variables[2] == "tcp"{
        eth = &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x8847}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
            return nil
        }
        buffer = gopacket.NewSerializeBuffer()
        if err := gopacket.SerializeLayers(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true },
            eth, mpls, ip, tcp, payload); err != nil {
            return nil
            }
    // no mpls and udp 
    } else if len(variables[5]) == 0 && variables[2] == "udp" {
        eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
            return nil
        }
        buffer = gopacket.NewSerializeBuffer()
        if err := gopacket.SerializeLayers(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true },
            eth, ip, udp, payload); err != nil {
            return nil
            }
    // no mpls and tcp
    } else if len(variables[5]) == 0 && variables[2] == "tcp"{
        eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
            return nil
        }
        buffer = gopacket.NewSerializeBuffer()
        if err := gopacket.SerializeLayers(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true },
            eth, ip, tcp, payload); err != nil {
            return nil
            }
    // icmp
    } else if variables[2] == "icmp" {
        eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        buffer = gopacket.NewSerializeBuffer()
        if err := gopacket.SerializeLayers(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true },
            eth, ip, icmp); err != nil {
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

//Send crafted packets over wire
func PacketSend(device string, packet []byte, promiscuous bool) {
    var snapshot_len int32 = 65535
    //var promiscuous bool = false
    var timeout = 30 * time.Second
    handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {panic(err) }
    defer handle.Close()

    // Send raw bytes over wire
    err = handle.WritePacketData(packet)
    if err != nil {
        panic(err)
    }
}

// Print hex packet
func PrintHex(packet []byte) {
    str = hex.EncodeToString(buffer.Bytes())
    if len(str) != 0 {
        fmt.Println("\n============= Hex packet crafted ===========\n")
        fmt.Printf(str)
        fmt.Println("\n=================================================\n")
    }
}

// Main function
func main() {
    //Argparser
    parser := argparse.NewParser("Required-args", "\n=================\ngo packet crafter\n=================")
    sip := parser.String("S", "sip", &argparse.Options{Required: true, Help: "Source Ip address to use as outer IP header"})
    dip := parser.String("D", "dip", &argparse.Options{Required: true, Help: "Destination IP address to use as outer IP header"})
    sport := parser.String("s", "sport", &argparse.Options{Required: false, Help:"Source Port in outer IP header. Can be single integer or a range [1000-2000]"})
    dport := parser.String("d", "dport", &argparse.Options{Required: false, Help:"Destination Port in outer IP header. Can be single integer or a range [1000-2000]"})
    ptype := parser.String("t", "type", &argparse.Options{Required: true, Help:"Type of packet. Can be tcp, udp, icmp. if icmp then dont mention source and dest ports."})
    mpls := parser.String("l", "mpls", &argparse.Options{Required: false, Help:"Mpls labels. Can be single integer or a list such as [1000 2000] . In this case the first label would be bottom of the stack" })
    payload := parser.String("p", "payload", &argparse.Options{Required: false, Help:"optional payload string. if not provided, will use 'payload' as the payload in the packet" })
    smac := parser.String("m", "smac", &argparse.Options{Required: false, Help:"source MAC address" })
    dmac := parser.String("M", "dmac", &argparse.Options{Required: false, Help:"destination MAC address" })
    //pcap := parser.String("w", "write", &argparse.Options{Required: false, Help: "Write the crafted packet to pcap file"})
    intf := parser.String("i", "interface", &argparse.Options{Required: false, Help: "Interface over which we need to send the created packets"})
    promiscuous := parser.String("P", "promiscuous", &argparse.Options{Required: false, Help: "Optioinal param to enable Promiscuous mode for the interface which is a boolean value. use true to enable and false to disable. default is false if not mentioned"})
    hex := parser.String("H", "hexprint", &argparse.Options{Required: false, Help: "Optional param to print HEX data of the created packet. you can then use any decoder like wireshark or online tools"})    
    numpkts:= parser.String("n", "numpkt", &argparse.Options{Required: false, Help: "Number of packets to send over wire"})
  
    err := parser.Parse(os.Args)
    if err != nil {
        fmt.Print(parser.Usage(err))
    } else {
        /*  
        Pass the below arguments to craft the packet 
        Arglist in order: [Sourceip, DestinationIp, Type, Sourceport, Destinationport, mpls, payload, pcap] 
        */ 
        pkt := createPacket(*sip, *dip, *ptype, *sport, *dport, *mpls, *payload, *smac, *dmac)

        //if pcap != nil {
        //    fmt.Println("\n======= Storing into pcap file ===========\n")
        //    PcapCreate(*pcap, pkt)
        //}

        //print Hex packet 
        if len(*hex) != 0 && *hex == "true" {
            PrintHex(pkt)
        }

        // send packets over interface
        if len(*intf) != 0 {
            if *promiscuous =="true" {
                numpkt,_ := strconv.Atoi(*numpkts)
                interval := float64(1.0)/float64(numpkt)
                start := 0.0
                end := 1.0
                for i:=start ; i<end; i+=interval {
                    fmt.Printf("sending packet!!! %f\n",i)
                    PacketSend(*intf, pkt, true)
                }
            } else {
                numpkt,_ := strconv.Atoi(*numpkts)
                interval := float64(1.0)/float64(numpkt)
                start := 0.0
                end := 1.0
                for i:=start ; i<end; i+=interval {
                    fmt.Printf("sending packet!!! %f\n",i)
                    PacketSend(*intf, pkt, false)
                }
            }   
        } 
    }
}
