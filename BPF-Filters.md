# BPF Filter Examples for Network Sniffer

# Basic Protocol Filters
tcp                      # All TCP traffic
udp                      # All UDP traffic
icmp                     # All ICMP traffic
arp                      # All ARP traffic

# Port-Specific Filters
tcp port 80              # HTTP traffic
tcp port 443             # HTTPS traffic
udp port 53              # DNS traffic
tcp port 22              # SSH traffic
tcp port 21              # FTP traffic

# Host-Specific Filters
host 192.168.1.1         # Traffic to/from specific IP
src host 192.168.1.100   # Traffic from specific source
dst host 8.8.8.8         # Traffic to specific destination

# Network Filters
net 192.168.0.0/24       # Traffic from subnet
net 10.0.0.0/8           # Traffic from larger network

# Combination Filters
tcp and port 80          # TCP traffic on port 80
udp and not port 53      # UDP traffic except DNS
host 192.168.1.1 and tcp # TCP traffic with specific host

# Advanced Filters
tcp[tcpflags] & tcp-syn != 0  # SYN packets only
icmp[icmptype] == 8           # ICMP Echo Request (ping)
