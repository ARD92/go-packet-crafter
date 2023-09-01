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
                      ____         ____            _        _      ____            __ _
                     / ___| ___   |  _ \ __ _  ___| | _____| |_   / ___|_ __ __ _ / _| |_ ___ _ __
                    | |  _ / _ \  | |_) / _ |/ __| |/ / _ \ __| | |   |  __/ _ | |_| __/ _ \  __|
                    | |_| | (_) | |  __/ (_| | (__|   <  __/ |_  | |___| | | (_| |  _| ||  __/ |
                     \____|\___/  |_|   \__,_|\___|_|\_\___|\__|  \____|_|  \__,_|_|  \__\___|_|


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
  -v  --vni          vxlan vni id
  -x  --inpkt        Inner packet in hex format which can be used
  -T  --teid         TEID of GTPv1u packet. For the inner packet which is
                     tunneld, use inhex vals
  -i  --interface    Interface over which we need to send the created packets
  -P  --promiscuous  Optioinal param to enable Promiscuous mode for the
                     interface which is a boolean value. use true to enable and
                     false to disable. default is false if not mentioned
  -H  --hexprint     Optional param to print HEX data of the created packet.
                     you can then use any decoder like wireshark or online
                     tools
  -n  --numpkt       Number of packets to send over wire
  -I  --iptype       IP type. ipv4 or ipv6
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
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000 -d 1000 
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000-1002 -d 1000-1002 
```

#### Generate an ICMP packet and send over interface eth1
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t icmp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 
```

#### Generate a TCP/UDP packet with MPLS label[s]
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000-1002 -d 1000-1002 -l 1000
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000-1002 -d 1000-1002 -l 1000,1001,1002,1003
```

#### Use an interface in promiscuous mode
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000-1002 -d 1000-1002 -l 1000 -P true
```

#### Send a number of packets over the interface
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t udp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000-1002 -d 1000-1002 -l 1000 -n 100
```

#### Print hex format 
```
/go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t tcp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000 -d 1000 -H true
```

#### Create a packet with range of IP addresses and send out of interface 
IP addresses can be in ranges. i.e. each octet you can define the range that is needed. The range is split with a "-" followed by "." following IP addressing schemes.
```
1-3.2-3.4.3-5
```
In the above, There would be packets created with the below IPs
[1.2.4.3, 1.2.4.4, 1.2.4.5, 1.3.4.3, 1.3.4.4, 1.3.4.5, 2.2.4.3....... 3.3.4.5]


#### Create a VXLAN packet 
This has to be done in 2 steps. 
1. Create the inner packet and print the hex string 
```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t tcp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000 -d 1000 -H true
```
This will create a packet and print out a hex string such as `01ad0123fafb0242ac130003080045000031000000000006629eac130001ac13000203e803e80000000000000000500200002b410000676f7061796c6f6164`

2. Use the created inner packet in hex format and feed it as input to the vxlan packet. The destination port for vxlan has to be 4789 else wireshark doesnt decode as expected
```
./go-packet-crafter -S 192.19.0.1 -D 192.19.0.2 -t udp -m 03:41:AC:13:00:02 -M 03:41:AC:13:00:01 -i eth1 -s 1000 -d 4789 -v 1000 -H true -x 01ad0123fafb0242ac130003080045000031000000000006629eac130001ac13000203e803e80000000000000000500200002b410000676f7061796c6f6164
```

#### Create a GTP-U packet 
This will also be done in similar process as the VXLAN. i.e. 2 step process. Create the inner packet first and feed it as input to the GTP packet

```
./go-packet-crafter -S 172.19.0.1 -D 172.19.0.2 -t tcp -m 02:42:AC:13:00:03 -M 01:AD:01:23:fa:fb -i eth1 -s 1000 -d 1000 -H true
```
This will create a packet and print out a hex string such as `01ad0123fafb0242ac130003080045000031000000000006629eac130001ac13000203e803e80000000000000000500200002b410000676f7061796c6f6164`

2. Use the created inner packet in hex format and feed it as input to the GTP packet. use the `-T` flag for TEID value. Also note that destination port is 2152.
```
./go-packet-crafter -S 192.19.0.1 -D 192.19.0.2 -t udp -m 03:41:AC:13:00:02 -M 03:41:AC:13:00:01 -i eth1 -s 2152 -d 2152 -T 1000 -H true -x 01ad0123fafb0242ac130003080045000031000000000006629eac130001ac13000203e803e80000000000000000500200002b410000676f7061796c6f6164
```

#### Create an IPv6 UDP packet
Currently there is a limit of single source IP and destionation IP. Range of IPaddresses within a subnet is WIP 

```
root@ubuntu:~/go-packet-crafter# ./go-packet-gen --smac 02:aa:01:40:01:00 --dmac 02:aa:01:10:02:01 -I ipv6 -i eth1 -t udp -S 3010:1122:1101:0100:0000:0C08:0A01:0001  -D 2001:db8:1111:2222:0078:0100:2000:0000 -s 1090 -d 80 -n 1000000
```

#### Create an IPv6 ICMPv6 packet
```
root@ubuntu:~/go-packet-crafter# ./go-packet-gen --smac 02:aa:01:40:01:00 --dmac 02:aa:01:10:02:01 -I ipv6 -i eth1 -t icmp6 -S 3010:1122:1101:0100:0000:0C08:0A01:0001 -D 2001:db8:1111:2222:0078:0100:2000:0000 -n 1000000
```

