# coding: utf-8
from scapy.all import *
from collections import OrderedDict
import subprocess
import re
class Devices(object):
	def __init__(self):
		ips = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.',subprocess.check_output(["ip","a"]).decode("ascii")) 
		self.networks = list(set(x for x in ips if not x.startswith("127")))
		self.target_list = (list(self.networks)[-1]+str(x) for x in range(1,255))
		self.device_dict = OrderedDict()
		self.scan()
	def scan(self):
		ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = self.target_list), timeout = 2)
		for snd, rcv in ans:
			self.device_dict[str(rcv.psrc)]=str(rcv.hwdst)

if __name__ == "__main__":
	d = Devices()
	for k,v in d.device_dict.items():
		print("IP: ", k, "MAC", v)

