from scapy.all import *
from collections import OrderedDict
from threading import Thread, Event
import time
class PacketSniffer(object):
    def __init__(self, interface = 'wlan0'):
        self.interface = interface
        self.packet = None
        self.cookie = False

    def fetch(self, packet):
        data = OrderedDict()
        data = {"no":"-",
            "time":"-",
            "ips":"-",
            "macs":packet.src,
            "ports":"-",
            "ipd":"-",
            "macd":packet.dst, 
            "portd":"-",
            "sum" : packet.summary()}
        while packet:
            if type(packet) is NoPayload:
                break
            elif type(packet) is IP:
                data["ips"] = packet.src
                data["ipd"] = packet.dst
            elif type(packet) is TCP:
                data["ports"] = packet.sport
                data["portd"] = packet.dport
            elif type(packet) is UDP:
                data["ports"] = packet.sport
                data["portd"] = packet.dport
            packet = packet.payload
        return data

    def run(self):
        if self.cookie:                                  #2
            yield self.fetch(sniff(filter= "Ether", iface=self.interface, store = 1, count=1)[-1])
        
def hammerOn(ps):
     while ps.cookie:
            packet = ps.run().__next__()
            data = {"no":"",
            "time":"",
            "ips":"-",
            "macs":packet.src,
            "ports":"-",
            "ipd":"-",
            "macd":packet.dst, 
            "portd":"-",
            "sum" : packet.summary()}
            while packet:
                if type(packet) is NoPayload:
                    break
                elif type(packet) is IP:
                    data["ips"] = packet.src
                    data["ipd"] = packet.dst
                elif type(packet) is TCP:
                    data["ports"] = packet.sport
                    data["portd"] = packet.dport
                elif type(packet) is UDP:
                    data["ports"] = packet.sport
                    data["portd"] = packet.dport
                packet = packet.payload
           
if __name__ == "__main__":
    ps = PacketSniffer()
    ps.cookie = True
    while ps.cookie:
        print(ps.run().__next__())
    #hammerOn(ps)

   
    #ps.run()