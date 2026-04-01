ZMap: The Internet Scanner
==========================

![Build Status](https://github.com/zmap/zmap/actions/workflows/cmake.yml/badge.svg)

ZMap is a fast stateless single packet network scanner designed for Internet-wide network
surveys. On a typical desktop computer with a gigabit Ethernet connection, ZMap
is capable of scanning the entire public IPv4 address space on a single port in 
under 45 minutes. For example, sending a TCP SYN packet to every IPv4 address
on port 25 to find all potential SMTP servers running on that port. With a 
10gigE connection and [netmap](http://info.iet.unipi.it/~luigi/netmap/) or 
[PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/), ZMap can scan 
the IPv4 address space in under 5 minutes.

ZMap operates on GNU/Linux, Mac OS, and BSD. ZMap currently has fully implemented
probe modules for TCP SYN scans, ICMP, DNS queries, UPnP, BACNET, and can send a
large number of [UDP probes](https://github.com/zmap/zmap/blob/master/examples/udp-probes/README).
If you are looking to do more involved scans (e.g., banner grab or TLS handshake), 
take a look at [ZGrab 2](https://github.com/zmap/zgrab2), ZMap's sister project 
that performs stateful application-layer handshakes.


Using ZMap
----------

If you haven't used ZMap before, we have a step-by-step [Getting Started Guide](https://github.com/zmap/zmap/wiki/Getting-Started-Guide) that details how to perform basic scans. Documentation about all of ZMap's options and more advanced functionality can be found in our [Wiki](https://github.com/zmap/zmap/wiki). For best practices, see [Scanning Best Practices](https://github.com/zmap/zmap/wiki/Scanning-Best-Practices). 

If you have questions, please first check our [FAQ](https://github.com/zmap/zmap/wiki/FAQ). Still have questions? Ask the community in [Github Discussions](https://github.com/zmap/zmap/discussions/categories/q-a). Please do not create an Issue for usage or support questions.

Installation
------------

The latest stable release of ZMap is  [4.3.1](https://github.com/zmap/zmap/releases/tag/v4.3.1) and supports Linux, macOS, and
BSD. See [INSTALL](INSTALL.md) for instructions on to install ZMap through a package manager or from source.

Architecture
------------

More information about ZMap's architecture and a comparison with other tools can be found in these research papers:

 * [ZMap: Fast Internet-Wide Scanning and its Security Applications](https://zmap.io/paper.pdf)
 * [Zippier ZMap: Internet-Wide Scanning at 10 Gbps](https://jhalderm.com/pub/papers/zmap10gig-woot14.pdf)
 * [Ten Years of ZMap](https://arxiv.org/pdf/2406.15585)

If you use ZMap for published research, please cite the original research paper:

```
@inproceedings{durumeric2013zmap,
  title={{ZMap}: Fast Internet-wide scanning and its security applications},
  author={Durumeric, Zakir and Wustrow, Eric and Halderman, J Alex},
  booktitle={22nd USENIX Security Symposium},
  year={2013}
}
```

Citing the ZMap paper helps us to track ZMap usage within the research community and to pursue funding for continued development.


IPv6 support
------------

We added IPv6 support to ZMap and include the following new probe modules:

* ICMPv6 Echo Request: `icmp6_echoscan`
* IPv6 TCP SYN (any port): `ipv6_tcp_synscan` or `ipv6_tcp_synopt`
* IPV6 UDP (any port and payload): `ipv6_udp`
* IPV6 DNS (any port): `ipv6_dns`

You can specify the respective IPv6 probe module using the `-M` or `--probe-module` command line flag.

In addition, you need to specify the source IPv6 address with the `--ipv6-source-ip` flag and a file containing IPv6 targets using the `--ipv6-target-file` flag.
More information can be found using the `--help` flag.

As targets for your IPv6 measurements you can e.g. use addresses from our [IPv6 Hitlist Service](https://ipv6hitlist.github.io/).

QUIC Probe module
-----------------------

We added probe modules for IPv4 and IPv6 to detect QUIC capable hosts based on the Version negotiation as described in [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000)

To start the scanner enter:

```bash
zmap -q -M quic_initial -p"443" --output-module="csv" \
-f "saddr,classification,success,versions" -o "output.csv" \
--probe-args="padding:1200" "$address/$netmask"
```

* `-q`: silent / without stdout
* `-p`: port, usually 443 for QUIC
* `-M quic_initial`: loads our QUIC probe module
* `--output-module=csv`: save as csv
* `-f "..."`: specifies fields that will be stored in the output file
* `-o output.csv`: name of the output file
* `--probe-args="padding:X"` [optional]: changes default padding to X bytes
* `$address`: IPv4 address
* `$netmask`: 0-32


The Initial packet should be at least 1200 Bytes long according to the specification.
The default padding is 1200 - sizeof(long_quic_header) [22 Bytes] = 1178 Bytes

With the `--probe-args="padding:X"` argument, we can scan target using Initial packets 
that do not follow the current specification. 
* Default: X=1178
* Initial packets without padding: X=0
* Initial packets with size 300: X=278

IPv6 DNS Probe Moodule
---------------------

We added IPv6 DNS support to ZMap.
To start the scanner enter (replace all variables with your system value [$interface,$node_ip,$target_file,$logfile,$gatewaymac):

```bash
zmap \
        --interface="$interface" \
        --ipv6-source-ip="$node_ip" \
        --ipv6-target-file="$target_file" \
        --target-port=53 \
        --probe-module=ipv6_dns \
        --probe-args="AAAA,www.google.com" \
        --blocklist-file=/etc/zmap/blocklist.conf \
        --rate=55000\
        --gateway-mac=$gatewaymac
```
* `--interface`: specify interface
* `$interface`: valid interface of scanning device
* `--ipv6-source-ip`: specify IPv6 source address
* `$node_ip`: IPv6 address
* `--ipv6-target-file`: file with ipv6 addresses which shall be scanned
* `$target_file`: path to scan file
* `--target-port`: port, usually 53 for DNS
* `--probe-module=ipv6_dns`: loads IPv6 DNS module
* `--probe-args="AAAA,www.google.com"`: format is [QTYPE],[QNAME] - qtype support for "A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA", "RRSIG", "ALL"
* `--blocklist-file=/etc/zmap/blocklist.conf`: default blocklist file (addresses in there are skipped during scan)
* `--rate=55000`: scan rate in packets per second
* `--gateway-mac`: optional MAC address, may be necessary if scanning node has multiple interfaces and you are using a non-default interface
* `$gatewaymac`: MAC address of the specified interface

TunnelSAV (ISAV / OSAV) Measurement Commands
--------------------------------------------

This repository also includes TunnelSAV probe modules for:

* `ipip`
* `gre`
* `ip6ip6`
* `gre6`
* `4in6`
* `6to4`

Where:

* **ISAV (Ingress SAV)**: filters packets entering the network with spoofed internal source addresses.
* **OSAV (Egress SAV)**: filters packets leaving the network with spoofed/non-local source addresses.

### Input files

* IPv4 target list: `--list-of-ips-file <targets_v4.txt>`
* IPv6 target list: `--ipv6-target-file <targets_v6.txt>`

### Notes

* Replace interface / source IP / target file paths with your local environment.
* Use `sudo` if raw socket access requires privileges.
* For `ipip_isav` and `gre_isav`, received IPv4 ICMP packets destined to local IPv4 are counted as matches; source IPv4s are deduplicated before writing to result CSV.

### 1) `ipip_isav`

```bash
sudo zmap -M ipip_isav \
  --interface=eno1 \
  --list-of-ips-file=targets_v4.txt \
  -S 101.6.20.79 \
  --probe-args="inner_dst4=101.6.20.79" \
  -f "saddr,daddr,classification,success,mode,proto,response_src" \
  -o ipip_isav.csv
```

### 2) `ipip_osav`

```bash
sudo zmap -M ipip_osav \
  --interface=eno1 \
  --list-of-ips-file=targets_v4.txt \
  -S 101.6.20.79 \
  --probe-args="inner_src4=202.112.237.226,inner_dst4=101.6.20.79" \
  -f "*" \
  -o ipip_osav.csv
```

### 3) `gre_isav`

```bash
sudo zmap -M gre_isav \
  --interface=eno1 \
  --list-of-ips-file=targets_v4.txt \
  -S 101.6.20.79 \
  --probe-args="inner_dst4=101.6.20.79" \
  -f "saddr,daddr,classification,success,mode,proto,response_src" \
  -o gre_isav.csv
```

### 4) `gre_osav`

```bash
sudo zmap -M gre_osav \
  --interface=eno1 \
  --list-of-ips-file=targets_v4.txt \
  -S 101.6.20.79 \
  --probe-args="inner_src4=202.112.237.226,inner_dst4=101.6.20.79" \
  -f "*" \
  -o gre_osav.csv
```

### 5) `6to4_isav`

```bash
sudo zmap -M 6to4_isav \
  --interface=eno1 \
  --list-of-ips-file=targets_v4.txt \
  --probe-args="inner_dst6=2402:f000:6:1401:1618:77ff:fe53:619,spoofing-address-v6=2001:da8:ff:212::10:4" \
  -f "saddr,classification,success,scheme_type,payload_info,replied_v6_src" \
  -o 6to4_isav.csv
```

### 6) `6to4_osav`

```bash
sudo zmap -M 6to4_osav \
  --interface=eno1 \
  --ipv6-source-ip=2402:f000:6:1401:1618:77ff:fe53:619 \
  --ipv6-target-file=targets_v6.txt \
  --probe-args="inner_src6=2001:13b0:8001:af03::116,inner_dst4=101.6.20.79,inner_src4=202.112.237.226" \
  -f "classification,success,response_src,original_target,icmp_type,payload_outer_dst4,payload_outer_dst6,payload_inner_src4,payload_inner_dst4,payload_inner_src6,payload_inner_dst6" \
  -o 6to4_osav.csv
```

### 7) `ip6ip6_isav`

```bash
sudo zmap -M ip6ip6_isav \
  --interface=eno1 \
  --ipv6-source-ip=2402:f000:6:1401:1618:77ff:fe53:619 \
  --ipv6-target-file=targets_v6.txt \
  --probe-args="inner_dst6=2402:f000:6:1401:1618:77ff:fe53:619" \
  -f "saddr,daddr,classification,success,mode,proto,response_src" \
  -o ip6ip6_isav.csv
```

### 8) `ip6ip6_osav`

```bash
sudo zmap -M ip6ip6_osav \
  --interface=eno1 \
  --ipv6-source-ip=2402:f000:6:1401:1618:77ff:fe53:619 \
  --ipv6-target-file=targets_v6.txt \
  --probe-args="inner_src6=2001:db8:ffff::9,inner_dst6=2402:f000:6:1401:1618:77ff:fe53:619" \
  -f "*" \
  -o ip6ip6_osav.csv
```

### 9) `gre6_isav`

```bash
sudo zmap -M gre6_isav \
  --interface=eno1 \
  --ipv6-source-ip=2402:f000:6:1401:1618:77ff:fe53:619 \
  --ipv6-target-file=targets_v6.txt \
  --probe-args="inner_dst6=2402:f000:6:1401:1618:77ff:fe53:619" \
  -f "saddr,daddr,classification,success,mode,proto,response_src" \
  -o gre6_isav.csv
```

### 10) `gre6_osav`

```bash
sudo zmap -M gre6_osav \
  --interface=eno1 \
  --ipv6-source-ip=2402:f000:6:1401:1618:77ff:fe53:619 \
  --ipv6-target-file=targets_v6.txt \
  --probe-args="inner_src6=2001:da8:ff:212::10:4,inner_dst6=2402:f000:6:1401:1618:77ff:fe53:619" \
  -f "original_target,icmp_type,payload_outer_dst6,payload_inner_src6,payload_inner_dst6" \
  -o gre6_osav.csv
```

### 11) `4in6_isav`

```bash
sudo zmap -M 4in6_isav \
  --interface=eno1 \
  --ipv6-source-ip=2402:f000:6:1401:1618:77ff:fe53:619 \
  --ipv6-target-file=targets_v6.txt \
  --probe-args="inner_dst4=101.6.20.79" \
  -f "saddr,daddr,classification,success,mode,proto,response_src" \
  -o 4in6_isav.csv
```

### 12) `4in6_osav`

```bash
sudo zmap -M 4in6_osav \
  --interface=eno1 \
  --ipv6-source-ip=2402:f000:6:1401:1618:77ff:fe53:619 \
  --ipv6-target-file=targets_v6.txt \
  --probe-args="inner_dst4=101.6.20.79,inner_src4=202.112.237.226" \
  -f "saddr,classification,success,original_target,icmp_type,mode,proto,response_src,payload_outer_dst4" \
  -o 4in6_osav.csv
```

License and Copyright
---------------------

ZMap Copyright 2024 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
