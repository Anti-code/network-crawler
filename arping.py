# coding: utf-8
from scapy.all import *
from collections import OrderedDict

class Devices(object):
	def __init__(self, target_list = ["10.99.5."+str(x) for x in range(1,255)]):
		self.device_dict = OrderedDict()
		self.target_list = target_list
		self.scan()

	def scan(self):
		for ip in ["10.99."+str(x%16)+"."+str(x) for x in range(1,255)]:
			print("tried-"+ip)
			ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 0.05)
			for snd, rcv in ans:
				self.device_dict[str(rcv.psrc)]=str(rcv.hwdst)

if __name__ == "__main__":
	d = Devices()
	for k,v in d.device_dict.items():
		print("IP: ", k, "MAC", v)

