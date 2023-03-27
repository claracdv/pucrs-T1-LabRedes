from socket import *
from binascii import hexlify

# Nivel de -Enlace-
ARP = 'arp'
ARP_REQUEST = 'arp_request'
ARP_REPLY = 'arp_reply'

# Nivel de -Rede-
IPV4 = 'ipv4'

ICMP = 'icmp'
ICMP_ECHOREQUEST = 'icmp_echorequest'
ICMP_ECHOREPLY = 'icmp_echoreply'

IPV6 = 'ipv6'

ICMPV6 = 'icmpv6'
ICMPV6_ECHOREQUEST = 'icmpv6_echorequest'
ICMPV6_ECHOREPLY = 'icmpv6_echoreply'

# Nivel de -Transporte-
TCP = 'tcp'
UDP = 'udp'

s = socket(AF_PACKET, SOCK_RAW, ntohs(3))



for _ in range(10):
    packet = s.recv(65535)

    packet = hexlify(packet).decode("utf-8")

    ethernet_header = packet[:28]
    network_protocol = ethernet_header[24:]
    packet = packet[28:]

    print(network_protocol)

    ipv4(packet)