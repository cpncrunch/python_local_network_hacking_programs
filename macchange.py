#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-02-2022
#Description: Simple program to change your MAC address

import subprocess

def change_mac_address(interface, mac):
	subprocess.call(["ifconfig " + interface + " down"])
	subprocess.call(["ifconfig " + "hw " + "ether " + mac])
	subprocess.call(["ifconfig " + interface + " up"])

def main():
	interface = str(input("[*] Enter interface to change MAC address on: "))
	new_mac_address = input("[+] Enter new MAC address: ")
	
	before_change = subprocess.check_output(["ifconfig " + interface])
	change_mac_address(interface, new_mac_address)
	after_change = subprocess.check_output(["ifconfig " + interface])
	
	if before_change == after_change:
		print("[!] Failed to change MAC address to: " + new_mac_address)
	else:
		print("[+] MAC address changed to: " + new_mac_address + " on interface " + interface)

main()
