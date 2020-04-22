#!/usr/bin/python
from scapy.all import *


def secret_filter(packet):
    return UDP in packet and packet[UDP].sport == 6000


def main():
    ok = True
    word = ''
    while ok:
        tav_packet = sniff(count=1, lfilter=secret_filter)
        number = tav_packet[0][UDP].dport - 5000
        if chr(number) != '!':
            word += chr(number)
            send(IP(dst='127.0.0.1') / UDP(sport=6000, dport=ord('!')), verbose=0)
        else:
            ok = False
    print word


if __name__ == '__main__':
    main()
