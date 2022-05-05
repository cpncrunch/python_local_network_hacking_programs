#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-03-2022
#Description: Python program to sniff MAC addresses form source and destination of received packets

import socket
from struct import *

def eth_addr(a):
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
	return b

def main():
	try:
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	except:
		print("[!] Unable to create socket object")
		exit(0)

	while True:
		packet = s.recvfrom(65535)
		packet = packet[0]
		
		eth_length = 14
		eth_header = packet[:eth_length]
		
		eth = unpack('!6s6sH', eth_header)
		eth_protocol = socket.ntohs(eth[2])
		print("[+] Destination MAC: " + eth_addr(packet[0:6]) + ' [+] Source MAC: ' + eth_addr(packet[6:12]) + '[+] Protocol: ' + str(eth_protocol))
	
main()
