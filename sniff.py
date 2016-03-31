from scapy.all import *
from collections import OrderedDict
from threading import Thread, Event
import time
from Packet import DefaultPacket

class PacketSniffer(object):
    def __init__(self, interface='wlan0'):
        self.interface = interface
        self.cookie = False
        self.num = 1

    def fetch(self, packet):
        data = DefaultPacket()
        data.whole = packet.command()
        data.source_mac = packet.src
        data.destination_mac = packet.dst
        data.time = packet.time
        data.summary = packet.summary()
        data.no = self.num
        while packet:
            if type(packet) is NoPayload:
                break
            elif type(packet) is IP:
                data.source_ip = packet.src
                data.destination_ip = packet.dst
            elif type(packet) is (TCP or UDP):
                data.source_port = packet.sport
                data.destination_port = packet.dport
            packet = packet.payload

        self.num += 1
        return data

    def run(self):
        if self.cookie:  # 2
            p = self.fetch(sniff(filter="Ether", iface=self.interface, store=1, count=1)[-1])
            return p


if __name__ == "__main__":
    ps = PacketSniffer()

    #print(ps.run().__next__())
        # hammerOn(ps)


        # ps.run()
