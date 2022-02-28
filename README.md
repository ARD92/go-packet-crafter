# GO-PACKET-CRAFTER 
A simple packet crafter built using gopacket. useful for testing purposes where we need to simulate traffic.
This is not aimed at packet generation for performance measurements but more from a point of functionality tests

## Get the package
### Clone the package
```
git clone https://github.com/ARD92/go-packet-crafter.git
```

### Build the container
```
cd go-container
docker build -t go-packet-crafter:v1.0 .
```

## Usage
Below commands can be used to craft packets and send out of the interface. 

```
=================
go packet crafter
=================

Arguments:

  -h  --help         Print help information
  -S  --sip          Source Ip address to use as outer IP header
  -D  --dip          Destination IP address to use as outer IP header
  -s  --sport        Source Port in outer IP header. Can be single integer or a
                     range 1000-2000
  -d  --dport        Destination Port in outer IP header. Can be single integer
                     or a range 1000-2000
  -t  --type         Type of packet. Can be tcp, udp, icmp. if icmp then dont
                     mention source and dest ports.
  -l  --mpls         Mpls labels. Can be single integer or a label stack such
                     as 1000,2000,3000 . In this case the first label would be
                     bottom of the stack
  -p  --payload      optional payload string. if not provided, will use
                     'payload' as the payload in the packet
  -m  --smac         source MAC address
  -M  --dmac         destination MAC address
  -i  --interface    Interface over which we need to send the created packets
  -P  --promiscuous  Optioinal param to enable Promiscuous mode for the
                     interface which is a boolean value. use true to enable and
                     false to disable. default is false if not mentioned
  -H  --hexprint     Optional param to print HEX data of the created packet.
                     you can then use any decoder like wireshark or online
                     tools
  -n  --numpkt       Number of packets to send over wire
```
* -s/-d or --sport/--dport can be used with a single value or a range. 
    -s 1000 or -s 1000-2000. 
    -d 1000 or -d 1000-2000
    In case of 1000-2000, every packet would be generated cycling through UDP ports 1000, 1001, 1002 and so on..
* -l or --mpls can be single label value or a stack 
    -l 1000 or -l 1000,2000,3000

### Usage examples

#### Generate a TCP packet (SYN)  and send the packet over interface eth1
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t tcp -m 02:42:AC:13:00:03 -i eth1 -s 1000 -d 1000 

./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t tcp -m 02:42:AC:13:00:03 -i eth1 -s 1000-1002 -d 1000-1002 
```

#### Generate a UDP packet and send over interface eth1
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -i eth1 -s 1000 -d 1000 
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -i eth1 -s 1000-1002 -d 1000-1002 
```

#### Generate an ICMP packet and send over interface eth1
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t icmp -m 02:42:AC:13:00:03 -i eth1 
```

#### Generate a TCP/UDP packet with MPLS label[s]
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -i eth1 -s 1000-1002 -d 1000-1002 -l 1000
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -i eth1 -s 1000-1002 -d 1000-1002 -l 1000,1001,1002,1003
```

#### Use an interface in promiscuous mode
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -i eth1 -s 1000-1002 -d 1000-1002 -l 1000 -P true
```

#### Send a number of packets over the interface
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -i eth1 -s 1000-1002 -d 1000-1002 -l 1000 -n 100
```
