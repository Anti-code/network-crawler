from scapy.all import *
from io import StringIO

def layerdecorator(func):
    def func_wrapper(data):
        packet_st = {}
        try:
            for layer in [x.command() for x in func(data)]:
                continue
            return [x.command() for x in func(data)]
        except IndexError as e:
            return [x.command() for x in func(data)]
            #do stuff here
    return func_wrapper

class PacketSniffer(object):
    def __init__(self, interface = 'wlan0', hold = 1, tm = 200, amount = 1):
        self.packet_list = []
        sniff(iface = interface,  store = hold, timeout = tm, count = amount, prn = lambda x: self.packet_list.append(x))

    @layerdecorator
    def parseToLayers(self):
    # Parses the packet to  the protocol layers and returns all the layers in a list
        for data in self.packet_list:
            yield data
            while data.payload:
                data = data.payload
                yield data

    def dataToString(self):
        capture = StringIO()
        save_stdout = sys.stdout
        sys.stdout = capture
        for packet in self.packet_list:
            packet.comand()
        sys.stdout = save_stdout
        return capture.getvalue()
