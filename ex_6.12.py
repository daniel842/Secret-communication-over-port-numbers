#!/usr/bin/python
from scapy.all import *


def is_ip(s):
	for x in s:
		if not (x.isdigit() or x == '.'):
			return False
	return True


def make_new_ip(ip):
	new_ip = ''
	for num in reversed(ip.split('.')):
		new_ip += num + '.'
	return new_ip[:len(new_ip) - 1]


def return_IP(response_packet):
	if DNS in response_packet:
		if DNSRR in response_packet[DNS]:
			if response_packet[DNS].ancount == 1:
				return response_packet[DNS][DNSRR].rdata
			else:
				for i in xrange(response_packet[DNS].ancount):
					if is_ip(response_packet[DNS][DNSRR][i].rdata):
						return response_packet[DNS][DNSRR][i].rdata


def return_URL(response_packet):
	return response_packet[DNS][DNSRR].rdata


def main():
	while True:
		ns = raw_input()
		if 'nslookup' in ns and not is_ip(ns.replace('nslookup ', '')):
			dns_packet = IP(dst='8.8.8.8') / UDP(sport=24601, dport=53) / DNS(qdcount=1, rd=1) / DNSQR(
				qname=ns.replace('nslookup ', ''))
			response_packet = sr1(dns_packet, verbose=0)
			if response_packet[DNS].ancount != 0:
				print '>>>' + return_IP(response_packet)
			else:
				print "Wrong name"
		elif 'nslookup' in ns and is_ip(ns.replace('nslookup ', '')):
			dns_packet = IP(dst='8.8.8.8') / UDP(sport=24601, dport=53) / DNS(qdcount=1, rd=1) / DNSQR(
				qname=make_new_ip(ns.replace('nslookup ', '')) + '.in-addr.arpa')
			dns_packet[DNS][DNSQR].qtype = 'PTR'
			response_packet = sr1(dns_packet, verbose=0)
			print '>>> ' + return_URL(response_packet)
		else:
			print 'Wrong input'


if __name__ == '__main__':
	main()
