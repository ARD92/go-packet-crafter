/* Packet crafter based on gopacket 
Author: Aravind Prabhakar
Version: 1.0
Description: simple go based packet generator for testing flows/firewall filters for vNF/cNFs. It can also
             be used to craft packets for other testing purposes. This is not intended to test performance. 
*/


package main

import (
    "fmt"
    "net"
    "encoding/hex"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/akamensky/argparse"
    "os"
    "strings"
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
var pkt []byte
var pktarray [] []byte

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
*/

func Vxlan(vni uint32, vlanflag bool) *layers.VXLAN {
    vxlan := &layers.VXLAN {
        ValidIDFlag: vlanflag, 
        VNI: vni,
        //GBPExtension:
        //GBPDontLearn:
        //GBPApplied:
        //GBPGroupPolicyID:
    }
    return vxlan
}

func createPacket(variables ...string) []byte {
    // variable declaration 
    var mplsarray [] *layers.MPLS
    var vxlan *layers.VXLAN
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
            protocol = layers.IPProtocolICMPv4
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
        if strings.Contains(variables[5], ",") {
            resultm:=strings.Split(variables[5], ",")
            for i:=0; i<=len(resultm)-1;i++ {
                val,_ := strconv.Atoi(resultm[i])
                if i == 0 {
                    // mpls bottom of stack
                    mpls = Mpls(uint32(val), true)
                } else {
                    // mpls not bottom of stack
                    mpls = Mpls(uint32(val), false)
                }
                mplsarray = append(mplsarray, mpls)
            }
        // fix else condition. Single label fails. 
        } else {
            val,_ := strconv.Atoi(variables[5])
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
        smac,_ = net.ParseMAC(variables[7])
    } else {
        smac,_ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
        fmt.Println("using broadcast address for Source MAC")
    }

    // dmac[8]
    if len(variables[8]) != 0 {
        dmac,_ = net.ParseMAC(variables[8])
    } else {
        dmac,_ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
        fmt.Println("using broadcast address for Dest MAC")
    }

    //vxlan[9]
    if len(variables[9]) != 0 {
        val,_ := strconv.Atoi(variables[9])
        // if vlan id then true
        vxlan = Vxlan(uint32(val), false)
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
        fmt.Println(" ======== MPLS packet with udp transport =========== \n")
        eth = &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x8847}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        buffer = gopacket.NewSerializeBuffer()
        if err := payload.SerializeTo(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                panic(err)
            }
        if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
            return nil
        }
        if err := udp.SerializeTo(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                panic(err)
            }
        if err := ip.SerializeTo(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                panic(err)
            }
        // Handle stack of mpls labels 
        for final:=0; final<=len(mplsarray)-1; final++ {
            mpl := mplsarray[final]
            if err := mpl.SerializeTo(buffer, 
                gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                    return nil
                }
            }
        if err := eth.SerializeTo(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                return nil
            }
    // mpls and tcp
    } else if len(variables[5]) != 0 && variables[2] == "tcp"{
        fmt.Println(" ======== MPLS packet with TCP =========== \n")
        eth = &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x8847}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        buffer = gopacket.NewSerializeBuffer()
        if err := payload.SerializeTo(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                panic(err)
            }
        if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
            return nil
        }
        if err := tcp.SerializeTo(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                panic(err)
            }
        if err := ip.SerializeTo(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                panic(err)
            }
        // Handle stack of mpls labels 
        for final:=0; final<=len(mplsarray)-1; final++ {
            mpl := mplsarray[final]
            if err := mpl.SerializeTo(buffer, 
                gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                    return nil
                }
            }
        if err := eth.SerializeTo(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true }); err != nil {
                return nil
            }
    // no mpls and udp 
    } else if len(variables[5]) == 0 && variables[2] == "udp" && len(variables[9]) == 0 {
        fmt.Println(" ======== IP packet with udp =========== \n")
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
        fmt.Println(" ======== IP packet with TCP ports =========== \n")
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
        fmt.Println(" ======== ICMP packet  =========== \n")
        eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        buffer = gopacket.NewSerializeBuffer()
        if err := gopacket.SerializeLayers(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true },
            eth, ip, icmp, payload); err != nil {
            return nil
            }
    // Vxlan
    } else if len(variables[9]) !=0 && variables[2] == "udp" {
        fmt.Printf("=============== VXLAN Packet %s==================\n ",variables[9])
        eth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
        ineth := &layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: 0x0800}
        ip := &layers.IPv4{Version: 4, DstIP: dipaddr, SrcIP: sipaddr, Protocol: protocol}
        inip := &layers.IPv4{Version: 4, DstIP: net.ParseIP("192.168.1.1"), SrcIP: net.ParseIP("192.168.2.1"), Protocol: protocol}
        if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
            return nil
        }
        buffer = gopacket.NewSerializeBuffer()
        if err := gopacket.SerializeLayers(buffer,
            gopacket.SerializeOptions {ComputeChecksums: true, FixLengths: true },
            eth, ip, udp, vxlan, ineth, inip); err != nil {
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
    if err != nil { panic(err) }
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

// Main function
func main() {
     Banner() 
    //Argparser
    parser := argparse.NewParser("Required-args", "\n=================\ngo packet crafter\n=================")
    sip := parser.String("S", "sip", &argparse.Options{Required: true, Help: "Source Ip address to use as outer IP header"})
    dip := parser.String("D", "dip", &argparse.Options{Required: true, Help: "Destination IP address to use as outer IP header"})
    sport := parser.String("s", "sport", &argparse.Options{Required: false, Help:"Source Port in outer IP header. Can be single integer or a range 1000-2000"})
    dport := parser.String("d", "dport", &argparse.Options{Required: false, Help:"Destination Port in outer IP header. Can be single integer or a range 1000-2000"})
    ptype := parser.String("t", "type", &argparse.Options{Required: true, Help:"Type of packet. Can be tcp, udp, icmp. if icmp then dont mention source and dest ports."})
    mpls := parser.String("l", "mpls", &argparse.Options{Required: false, Help:"Mpls labels. Can be single integer or a label stack such as 1000,2000,3000 . In this case the first label would be bottom of the stack" })
    payload := parser.String("p", "payload", &argparse.Options{Required: false, Help:"optional payload string. if not provided, will use 'payload' as the payload in the packet" })
    smac := parser.String("m", "smac", &argparse.Options{Required: false, Help:"source MAC address" })
    dmac := parser.String("M", "dmac", &argparse.Options{Required: false, Help:"destination MAC address" })
    vxlan := parser.String("v", "vni", &argparse.Options{Required: false, Help:"vxlan vni id" })
    //inhex := parser.String("x", "inpkt" &argparse.Options{Required: false, Help: "Inner packet in hex format which can be used" })
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
        if strings.Contains(*sport, "-") && strings.Contains(*dport, "-") {
            result := strings.Split(*sport, "-")
            result1 := strings.Split(*dport, "-")
            starts,_ := strconv.Atoi(result[0])
            ends,_ := strconv.Atoi(result[1])
            startd,_ := strconv.Atoi(result1[0])
            endd,_ := strconv.Atoi(result1[1])
            for i:=starts;i<=ends;i++ {
                for j :=startd;j<=endd;j++ {
                    pkt = createPacket(*sip, *dip, *ptype, strconv.Itoa(i), strconv.Itoa(j), *mpls, *payload, *smac, *dmac, *vxlan)
                    pktarray = append(pktarray, pkt)
                }
            }
        } else if strings.Contains(*sport, "-") && !strings.Contains(*dport, "-") {
            result := strings.Split(*sport, "-")
            starts,_ := strconv.Atoi(result[0])
            ends,_ := strconv.Atoi(result[1])
            for i:=starts;i<=ends;i++ {
                pkt = createPacket(*sip, *dip, *ptype, strconv.Itoa(i), *dport, *mpls, *payload, *smac, *dmac, *vxlan)
                pktarray = append(pktarray, pkt)
            }
        } else if !strings.Contains(*sport, "-") && strings.Contains(*dport, "-") {
            result1 := strings.Split(*dport, "-")
            startd,_ := strconv.Atoi(result1[0])
            endd,_ := strconv.Atoi(result1[1])
            for j :=startd;j<=endd;j++ {
                pkt = createPacket(*sip, *dip, *ptype, *sport, strconv.Itoa(j), *mpls, *payload, *smac, *dmac, *vxlan)
                pktarray = append(pktarray, pkt)
            }            
        } else {
            pkt = createPacket(*sip, *dip, *ptype, *sport, *dport, *mpls, *payload, *smac, *dmac, *vxlan)
            fmt.Println(pkt)
        }

        //if pcap != nil {
        //    fmt.Println("\n======= Storing into pcap file ===========\n")
        //    PcapCreate(*pcap, pkt)
        //}

        // send packets over interface
        if len(*intf) != 0 {
            if *promiscuous =="true" {
                fmt.Printf("Sending packet over %s in promiscuous mode....\n ",*intf)
                numpkt,_ := strconv.Atoi(*numpkts)
                interval := float64(1.0)/float64(numpkt)
                start := 0.0
                end := 1.0
                for i:=start ; i<end; i+=interval {
                    if len(pktarray) != 0 {
                        for p:=0 ; p<=len(pktarray)-1; p++ {
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
                fmt.Printf("Sending packet over %s....\n ",*intf)
                numpkt,_ := strconv.Atoi(*numpkts)
                interval := float64(1.0)/float64(numpkt)
                start := 0.0
                end := 1.0
                for i:=start ; i<=end; i+=interval {
                    if len(pktarray) != 0 {
                        for p:=0; p<=len(pktarray)-1;p++ {
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
