#! usr/bin/env python3

import scapy.all as scp
import argparse

def scan(ip):
    arp_req = scp.ARP(pdst=ip)
    broadcast = scp.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_req
    answered_list = scp.srp(arp_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        print(element[1].psrc + "      " + element[1].hwsrc)
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-------------------------------------------")
    for client in results_list:
        print(client["ip"]+"\t\t"+client["mac"])


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",
                        help="Target IP/ IP range")
    options = parser.parse_args()
    print(options.target)
    return options


options = get_args()
scan_result = scan(options.target)
print_result(scan_result)
