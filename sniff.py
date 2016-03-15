from scapy.all import *
from collections import OrderedDict
from threading import Thread
import time
class PacketSniffer():
    def __init__(self, interface = 'wlan0'):
        self.packet = None
        Thread(target = sniff, kwargs = {"iface" : interface, "store" : 0, "prn" : lambda packet: self.packetToDict(packet)}, daemon = True).start()
    def packetToDict(self,data):
        packet = OrderedDict()
        packet["real"] = data
        while data:
            if type(data) is NoPayload:
                break
            packet["time"]=int(time.time())
            packet[data.name] = list(data.fields.values())
            data = data.payload
        self.packet = packet
if __name__ == "__main__":
    ps = PacketSniffer()
