import gi
gi.require_version("Gtk", "3.0")
from threading import Thread
from gi.repository import Gio

from gi.repository import Gtk
from multiprocessing import Process
from sniff import PacketSniffer
from arping import Devices
import subprocess, re, csv
from collections import OrderedDict
from scapy.all import *
class MonitoringHandler(object):
    # Programın başlangıcında tanımlanmak istenen değişkenler ve çalıştırılmak istenen fonksiyonlar __init__ içinde tanımlanır.
    def __init__(self):

        # pasif cihaz taramasını arka planda başlat
        Thread(target = self.passiveScanner, daemon=True).start()

        # Arayüz tasarımının yapıldığı .glade(xml) dosyasını okumak için Gtk modülünün Builder nesnesi kulanılır.
        self.builder = Gtk.Builder()
        # Tasarım dosyasını add_from_file fonksiyonuna göstererek tasarımı programa aktardık.
        self.builder.add_from_file("main_window.glade") 
        # Tasarımda eklediğimiz Sinyalleri(Event) programda aynı isimde yazdığımız fonksiyonlara bağlar.
        self.builder.connect_signals(self)

        # Ağdaki paketleri yakalamak için yazılan modül.
        self.ps = PacketSniffer(interface="wlan0")
        # yakalanan paketlerin orjinal hali bu listede tutulacak
        self.packet_list = []
        # get_object metodu ile tasarımdaki tabloyu programa aktardık.
        self.content_table = self.builder.get_object("content_table")
        
        # cihazları gösteren comboboxun tutulduğu layer
        self.activity_box = self.builder.get_object("activity_box")
        # vbox.pack_start(currency_combo, False, False, 0)

        # Paketlerin listelemek istediğimiz özelliklerini tabloda stun olarak ekledik.
        columns = ["No", "Time", "Source IP", "Source MAC", "Source Port", "Destination IP", "Destination MAC",
                   "Destination Port", "Summary"]
        for no, column in enumerate(columns):
            self.content_table.append_column(Gtk.TreeViewColumn(column, Gtk.CellRendererText(), text=no))

        # cihaz taramasını yapan sınıf
        self.devices = Devices()
        # tarama yapmak için kullanılacak buton ve eventi
        self.rescan_button = self.builder.get_object('rescan_button')
        self.rescan_button.connect("clicked", self.scan_devices)


        # ağdaki cihazların listeleneceği menü
        self.menubutton = self.builder.get_object("menubutton")
        self.menumodel = Gio.Menu()
        self.menumodel.append("IP\t\tMAC\t\tVendor")
        self.menubutton.set_menu_model(self.menumodel)

        #self.menubutton.connect("activate", self.scan_devices)

        # Yukarda tanımladığımız tabloda(content_table) göstermek istediğimiz verileri ListStore'da tutarız 
        self.liststore = Gtk.ListStore(str, str, str, str, str, str, str, str, str)
        # filter_new() ile filtrelediğimiz sonuçları tutacağımız bir list_store'a bağlı bir liste daha oluşturduk
        self.filter = self.liststore.filter_new()
        # tanımladığımız filtreye filtreleme işleminin yapıldığı metodu ekledik.
        self.filter.set_visible_func(self.onSearch)
        # filtre listesini verileri tuttuğumuz tabloya model olarak ekledik.
        self.content_table.set_model(self.filter)

        # Arayüzden filtereleme için oluşturduğumuz Entry'i(metin girişi) programa aktardık.
        self.filter_field = self.builder.get_object("filter_field")
        # Her karakter girildiğinde filtrelemesi için changed sinyalini kullandık 
        #ve filtreleyince tabloyu yenileyen reFilter metodunu bu sinyale bağladık 
        self.filter_field.connect("changed", self.reFilter)

        # Arayüzün tamamını içinde bulunduran ana pencereyi programa aktardık.
        self.window = self.builder.get_object("window")
        self.window.set_size_request(1200, 500)
        self.window.connect("delete-event", Gtk.main_quit)
        self.window.show()

        self.menu_observer = []

    # filtrelenen verilerin tutulduğu listeyi günceller. entry parametresi metin girişinin yapıldığı nesne(kullanılmadı) 
    def reFilter(self, entry):
        self.filter.refilter()

    # tablodaki verilerle girilen metini kıyaslayan metod. 
    # model verilerin gösterildiği tablo,  treetiter tablodaki verileri adres gösteren nesne, data kullanılmadı.
    def onSearch(self, model, treeiter, data= None):
        if self.filter_field.get_text() is "":
            return True
        
        else:
            query= self.filter_field.get_text()
            try:
                # tüm stunlarda sorgulama yapmak için for kullandık.
                for column in range(self.content_table.get_n_columns()+1):
                    value = self.liststore.get_value(treeiter, column)
                    # value metin girişine yazdığımız ifadeyi içeriyorsa True değeri döndürterek görüntülenmesini sağladık.
                    if str(self.filter_field.get_text()) in str(value) :
                        return True
            # sorgu sonucu tabloda gösterecek birşey yoksa hata verme
            except TypeError:
                pass

    # tablodaki bir satıra çift tıklandığında seçilen paketin tüm özelliklerini gösterir
    def onContentSelected(self, treeview, treeiter, path):
        show_details = Gtk.MessageDialog(self.content_table, 0, Gtk.MessageType.INFO, Gtk.ButtonsType.OK)
        show_details.format_secondary_text(self.packet_list[int(self.liststore[treeiter][0])])
        box = show_details.get_content_area()
        show_details.run()
        show_details.destroy()

    # Tabloya veri eklemek için kullandığımız metod.
    def append(self):
        # cookie değeri True ise paket yakalama yapılabilir.
        while self.ps.cookie:
            # run metodu paket yakalar
            packet = self.ps.run()
            # paketin asıl halini daha sonra gösterebilmek için bir listeye attık
            self.packet_list.append(packet.whole)
            # yakalanan paketi tabloya göstertdiğimiz listeye ekler
            self.liststore.insert(0, packet.toList())
            # tablonun en başındaki elemanı seçer.
            self.content_table.set_cursor(0)

    # paket yakalamayı başlatan metod
    def onSwitch(self, switch, _):
        # arayüzdeki arama butonu aktif edildiyse paket yakalama iznini True yapar
        if switch.get_active():
            self.ps.cookie = True
            # tabloya paket yakalayıp ekleyen metodu arayüzden bağımsız olarak başlatır.
            Thread(target=self.append, daemon=True).start() 
        else:
            self.ps.cookie = False

    # aktif tarama için kullanılan metod
    def scan_devices(self, _=None):
        for x in self.devices.scan():
            data = "  ".join(i for i in x.values()).strip()
            if data not in self.menu_observer:
                self.menu_observer.append(data)
                self.menumodel.append(data)

    def passiveScanner(self):
        sniff(iface='wlan0', prn=self.arp_monitor_callback, store=0)
    
    def arp_monitor_callback(self, pkt):
        if ARP in pkt:
            data = pkt["ARP"].psrc+"  "+pkt["ARP"].hwsrc+"  "+self.devices.getVendor(pkt["ARP"].hwsrc)
            if data not in self.menu_observer:
                self.menu_observer.append(data)
                self.menumodel.append(data)
            
if __name__ == "__main__":
    mw = MonitoringHandler()
    Gtk.main()
