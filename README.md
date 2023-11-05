# ICMP Echo and DNS in Python

These two files are some very crude ICMP Echo and DNS implementations I did for a networking class. I've implemented these with just Wireshark and the RFC themselves without referencing existing Python based DNS implementations. Only ICMP Echo is supported in the ICMP demo, and only A and CNAME record types are supported in the DNS demo.

Due to heavy time constraints, these implementations have not been throughly tested, and compatibility with existing implementations aren't perfect. However, this should be a reasonably extensive demonstration of serializing/deserializing binary network packets within python, as well as handling flags in bitfields.


# Usage

```sh
# make a venv and force copy the python interpreter to the venv
$ python -m venv . --copies

# add the appropriate capabilities to the copy of the python interpreter we have in the venv so it can send/receive raw packets and bind to ports lower than 1024
$ sudo setcap CAP_NET_BIND_SERVICE,CAP_NET_RAW+eip bin/python3

# ICMP Echo
$ ./ping.py 8.8.8.8

# Start DNS server
$ ./dns.py -s 

# Querying data from a real DNS server
$ ./dns.py -c -d www.github.com
Operating in client mode
DNS Resource Record: 
Name: www.github.com 
Type: CNAME 
Class: IN 
TTL: 3546 second(s) 
Data: github.com 

DNS Resource Record: 
Name: github.com 
Type: A 
Class: IN 
TTL: 4 second(s) 
Data: 20.248.137.48 

```