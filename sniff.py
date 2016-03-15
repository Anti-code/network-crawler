from scapy.all import *
from collections import OrderedDict
from threading import Thread, Event
import time
class PacketSniffer():
    def __init__(self, interface = 'wlan0'):
        self.packet = None
        self.interface = interface
        self._stop = Event()
        self.t = Thread(target = sniff,  kwargs = {"iface" : self.interface, "store" : 0, "prn" : lambda packet: self.packetToDict(packet)}, daemon = True)
        /*
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
    def run(self):
        self.t.start()
if __name__ == "__main__":
    ps = PacketSniffer()
