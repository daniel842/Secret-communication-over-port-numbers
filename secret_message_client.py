#!/usr/bin/python
from scapy.all import *


def secret_filter(packet):
    return IP in packet and UDP in packet and packet[UDP].sport == 6000


def main():
    word = raw_input("Enter a word: ")
    for x in word:
        secret_packet = IP(dst='127.0.0.1') / UDP(sport=6000, dport=5000 + ord(x))
        send(secret_packet, verbose=0)
        sniff(count=1, lfilter=secret_filter)

    secret_packet = IP(dst='127.0.0.1') / UDP(sport=6000, dport=5000 + ord('!'))
    send(secret_packet, verbose=0)


if __name__ == '__main__':
    main()
