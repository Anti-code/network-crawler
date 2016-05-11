
from scapy.all import *
from collections import OrderedDict
import subprocess
import re
import pandas

class Devices(object):
	def __init__(self):
		# ip route komutu ile ağ bilgisini al
		proc1 = subprocess.Popen(['ip', 'route'],stdout=subprocess.PIPE)
		# ağ ve subnetmask bilgisi için 'proto kerner scope link' içeren satırı çek
		proc2 = subprocess.Popen(['grep', 'proto kernel  scope link'],stdin=proc1.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		proc1.stdout.close()
		out, _ = proc2.communicate()
		# ağ bilgisini içeren satırdan regex kullanarak ağı çek
		self.ips = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0\/[0-9]{1,2}', out.decode('utf-8'))
		# mac adreslerinin ait oldugu firmaların listesi
		self.df = pandas.DataFrame.from_csv(open('oui.csv'))	
		
	def scan(self):
		devices = []
		device_dict= OrderedDict()
		answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = self.ips[0]), timeout = 2)
		for _, received in answered:
			device_dict = OrderedDict()
			device_dict["ip"]=received.psrc # IP
			device_dict["mac"]=received.hwsrc # MAC
			 # ff:ff:ff:ff:ff:ff -> FFFFFF
			try:
				device_dict["vendor"]= self.getVendor(received.hwsrc)
			except IndexError:
				device_dict["vendor"]="Unknown"
			devices.append(device_dict)
		return devices

	def getVendor(self, hwsrc):
		mac= "".join(hwsrc.split(":")[:3]).upper()
		return self.df[self.df['Assignment'] == mac]['Organization Name'].values[-1]

if __name__ == "__main__":
	d = Devices()
	dv = d.scan()
	print(dv)


