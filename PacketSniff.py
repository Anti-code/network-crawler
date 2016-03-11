from scapy.all import *
from io import StringIO
from collections import OrderedDict

class PacketSniffer(object):
    def __init__(self, interface = 'wlan0', hold = 1, tm = 200, amount = 1):
        self.packet = OrderedDict()
        sniff(iface = interface,  store = hold, timeout = tm, count = amount, prn = lambda x : self.parseToLayers(x))
    def parseToLayers(self,data):
        while data:
            if type(data) is NoPayload:
                break
            self.packet[data.name] = data.fields
            data = data.payload
        return data
