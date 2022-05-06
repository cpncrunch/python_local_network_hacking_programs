#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett	
#Date: 05-05-2022
#Description: Network Analyzer. Low level packet sniffer to analyze parts of packets

import socket
import os,sys
import struct
import binascii

sock_created = False
sniffer_socket = 0

def analyze_udp_header(data_recv):
	udp_hdr = struct.unpack('!4H', data_recv[:8])
	source_port = udp_hdr[0]
	dest_port = udp_hdr[1]
	length = udp_hdr[2]
	checksum = udp_hdr[3]
	data = data_recv[:8]
	
	print("_________________UDP Header__________________")
	print("Source: %hu " % source_port)
	print("Destination: %hu " % dest_port)
	print("Length: %hu " % length)
	print("Checksum: %hu " % checksum)
	return data
	
def analyze_tcp_header(data_recv):
	tcp_header = struct.unpack('!2H2I4H', data_recv[:20])
	source_port = tcp_header[0]
	dest_port = tcp_header[1]
	seq_num = tcp_header[2]
	ack_num = tcp_header[3]
	data_offset = tcp_header[4] >> 12
	reserved = (tcp_header[4] >> 6) & 0x03ff
	flag = tcp_header[4] & 0x003f
	window = tcp_header[5]
	checksum = tcp_header[6]
	urg_ptr = tcp_header[7]
	data = data_recv[20:]
	
	urg = bool(flag & 0x0020)
	ack = bool(flag & 0x0010)
	pch = bool(flag & 0x0008)
	rst = bool(flag & 0x0004)
	syn = bool(flag & 0x0002)
	fin = bool(flag & 0x0001)
	
	print("_________________TCP Header__________________")
	print("Source: %hu " % source_port)
	print("Destination: %hu " % dest_port)
	print("Seq: %hu " % seq_num)
	print("Ack: %hu " % ack_num)
	print("Flags: ")
	print("Urg: %hu " % urg)
	print("ack: %hu " % ack)
	print("pch: %hu " % pch)
	print("rst: %hu " % rst)
	print("syn: %hu " % syn)
	print("fin: %hu " % fin)
	print("Window size: %hu " % window)
	print("Checksum: %hu " % checksum)
	return data

def analyze_ip_header(data_recv):
	ip_hdr = struct.unpack('!6H4s4s', data_recv[:20])
	ver = ip_hdr[0] >> 12
	ihl = (ip_hdr[0] >> 8) & 0x0f
	tos = ip_hdr[0] & 0x0ff
	tot_len = ip_hdr[1]
	ip_id = ip_hdr[2]
	flags = ip_hdr[3] >> 13
	frag_offset = ip_hdr[3] & 0x1fff
	ip_ttl = ip_hdr[4] >> 8
	ip_proto = ip_hdr[4] & 0x00ff
	checksum = ip_hdr[5]
	src_address = socket.inet_ntoa(ip_hdr[6])
	dst_address =  socket.inet_ntoa(ip_hdr[7])
	data = data_recv[20:]
	
	print("_________________IP Header__________________")
	print("Version: %hu " % ver)
	print("IHL: %hu " % ihl)
	print("TOS: %hu " % tos)
	print("Length: %hu " % tot_len)
	print("ID: %hu " % ip_id)
	print("Offset: %hu " % frag_offset)
	print("TTL: %hu " % ip_ttl)
	print("Protocol: %hu " % ip_proto)
	print("Checksum: %hu " % checksum)
	print("Source IP: %s " % src_address)
	print("Destination IP: %s " % dst_address)
	
	if ip_proto == 6:
		tcp_udp = "TCP"
	elif ip_proto == 17:
		tcp_udp = "UDP"
	else:
		tcp_udp = "OTHER"
		
	return data, tcp_udp

def analyze_ether_header(data_recv):
	ip_bool = False
	
	eth_header = struct.unpack('!6s6sH', data_recv[:14])
	dest_mac = binascii.hexlify(eth_header[0])
	src_mac = binascii.hexlify(eth_header[1])
	proto = eth_header[2] >> 8
	data = data_recv[14:]
	
	print("_________________Ethernet Header__________________")
	print("[*] Destination MAC: %s:%s:%s:%s:%s:%s:" % (dest_mac[0:2],dest_mac[2:4],dest_mac[4:6],dest_mac[6:8],dest_mac[8:10],dest_mac[10:12]))
	print("[*] Source MAC: %s:%s:%s:%s:%s:%s:" % (src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12]))
	print("Protocol: %hu" %proto)
	
	if proto == 0x08:
		ip_bool = True
	return data, ip_bool

def main():
	global sock_created
	global sniffer_socket
	
	if sock_created == False:
		sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
		sock_created = True
		
	data_recv = sniffer_socket.recv(2048)
	os.system('clear')
	
	data_recv, ip_bool = analyze_ether_header(data_recv)
	if ip_bool:
		data_recv, tcp_udp = analyze_ip_header(data_recv)
	else:
		return
		
	if tcp_udp == "TCP":
		data_recv = analyze_tcp_header(data_recv)
	elif tcp_udp == "UDP":
		data_recv = analyze_udp_header(data_recv)
	else:
		return
while True:
	main()

