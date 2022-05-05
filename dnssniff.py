#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-04-2022
#Description: DNS sniffing python program

from scapy.all import *

def findDNS(packet):
	if packet.haslayer(DNS):
		print(packet[IP].src, packet[DNS].summary())


sniff(prn=findDNS)
