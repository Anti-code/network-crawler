from scapy.all import *
from collections import OrderedDict
from threading import Thread, Event
import time
from packet import DefaultPacket
import io
from contextlib import redirect_stdout

# ağdaki diğer cihazlarıda izleyebilmek için promiscous modunu True yaptık
conf.promisc = True

class PacketSniffer(object):
    # programın genelinde kullanacağımız verileri tanımladık.
    def __init__(self, interface='wlan0', protocol = "Ether"):
        # paket yakalanmak istenen ağ
        self.interface = interface
        self.protocol = protocol
        # paketleri yakalama izni
        self.cookie = False
        # ilk paketin numarası
        self.num = 0

    # yakalanan network paketini kullanılabilir hale getiren metod
    def refactor(self, packet):
        # düzenlediğimiz verileri içerecek yeni bir DefaultPacket nesnesi oluşturduk
        data = DefaultPacket()
        # ağ paketinin tüm verilerini kendi paketimize ekledik
        with io.StringIO() as buf, redirect_stdout(buf):
            packet.show()
            data.whole = buf.getvalue()
        # kaynak ve hedef MAC adreslerini paketimize ekledik (2. katman)
        data.source_mac = packet.src
        data.destination_mac = packet.dst
        # paketin oluşturulduğu zamanı ekledik
        data.time = packet.time
        # paketin amacını içeren özeti ekledik
        data.summary = packet.summary()
        # pakete numara atadık
        data.no = self.num
        # paketin payloadlarına(alt paketler) erişmek için while kullandık
        while packet:
            # erişilecek alt paket kalmayınca döngü biter
            if type(packet) is NoPayload:
                break
            # paket türü ip ise
            elif type(packet) is IP:
                # paketimize kaynak ve hedef iplerini ekledik(3. katman)
                data.source_ip = packet.src
                data.destination_ip = packet.dst
            # paket türü TCP veya UDP ise
            elif type(packet) is (TCP or UDP):
                # paketimize kaynak ve hedef portlarını ekledik
                data.source_port = packet.sport
                data.destination_port = packet.dport
            # bir alt pakete geçtik
            packet = packet.payload
        # paket numarasını artırdık
        self.num += 1
        # Yapılandırılan DefaultPacket'i döndürür
        return data

    # paket yakalamayı başlatan metod
    def run(self):
        if self.cookie:  # paket yakalama izni varsa
                    # sniff metodu ile bir paket yakala ve yakalanan paketi refactor metoduna yolla. DefaultPacket döndürür
            return self.refactor(sniff(filter=self.protocol, iface=self.interface, store=1, count=1)[-1])


if __name__ == "__main__":
    ps = PacketSniffer()
