import gi

gi.require_version("Gtk", "3.0")
from threading import Thread
from gi.repository import Gtk
from multiprocessing import Process
from sniff import PacketSniffer
from arping import Devices

class MonitoringHandler(object):
    # Programın başlangıcında tanımlanmak istenen değişkenler ve çalıştırılmak istenen fonksiyonlar __init__ içinde tanımlanır.
    def __init__(self):
        # Arayüz tasarımının yapıldığı .glade(xml) dosyasını okumak için Gtk modülünün Builder nesnesi kulanılır.
        self.builder = Gtk.Builder()
        # Tasarım dosyasını add_from_file fonksiyonuna göstererek tasarımı programa aktardık.
        self.builder.add_from_file("main_window.glade") 
        # Tasarımda eklediğimiz Sinyalleri(Event) programda aynı isimde yazdığımız fonksiyonlara bağlar.
        self.builder.connect_signals(self)

        # Ağdaki paketleri yakalamak için yazılan modül.
        self.ps = PacketSniffer(interface="wlan0")
        #
        self.packet_list = []
        # get_object metodu ile tasarımdaki tabloyu programa aktardık.
        self.content_table = self.builder.get_object("content_table")

        # Paketlerin listelemek istediğimiz özelliklerini tabloda stun olarak ekledik.
        columns = ["No", "Time", "Source IP", "Source MAC", "Source Port", "Destination IP", "Destination MAC",
                   "Destination Port", "Summary"]
        for no, column in enumerate(columns):
            self.content_table.append_column(Gtk.TreeViewColumn(column, Gtk.CellRendererText(), text=no))

        """
        #-------------- henüz tamamlanmadı ----------------------------------------#
        protocols = ["All", "ARP", "IP", "TCP", "UDP", "HTTP", "DNS"]
        self.protocols = self.builder.get_object("protocols_box")
        self.protocols.set_entry_text_column(0)
        self.protocols.connect("changed", self.reFilter)
        for protocol in protocols:
            self.protocols.append_text(protocol)
        # --------------------------------------------------------------------------#
        """     
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
        self.window.set_size_request(800, 500)
        self.window.connect("delete-event", Gtk.main_quit)
        self.window.show()

    # filtrelenen verilerin tutulduğu listeyi günceller. entry parametresi metin girişinin yapıldığı nesne(kullanılmadı) 
    def reFilter(self, entry):
        self.filter.refilter()

    # tablodaki verilerle girilen metini kıyaslayan metod. 
    # model verilerin gösterildiği tablo,  treetiter tablodaki verileri adres gösteren nesne, data kullanılmadı.
    def onSearch(self, model, treeiter, data= None):
        if self.filter_field.get_text() is "":
            return True
        else:
            # tüm stunlarda sorgulama yapmak için for kullandık.
            for column in range(self.content_table.get_n_columns()+1):
                    # Belirlenen stundaki verileri value değişkeninde tuttuk.
                    value = self.liststore.get_value(treeiter, column).lower()
                    # value metin girişine yazdığımız ifadeyi içeriyorsa True değeri döndürterek görüntülenmesini sağladık.
                    if self.filter_field.get_text() in value :
                        return True

    # tablodaki bir satıra çift tıklandığında seçilen paketin tüm özelliklerini gösterir(tamamlanmadı)
    def onContentSelected(self, treeview, treeiter, path):
        #self.liststore[treeiter][:]
        show_details = Gtk.MessageDialog(self.window, 0, Gtk.MessageType.INFO,Gtk.ButtonsType.OK)
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
            #
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

    def onDevicesToggled(self, button):
        if button.get_active:
            show_devices = Gtk.MessageDialog(self.window, 0, Gtk.MessageType.INFO)
            box = show_devices.get_content_area()
            show_devices.format_secondary_text("\n".join(str(x) for x in Devices().scan().items()))
            newmenu=Gtk.Menu()
            newitem=Gtk.MenuItem('hello')
            newmenu.append(newitem)
            newitem1=Gtk.MenuItem('goodbye')
            newmenu.append(newitem1)
            newmenu.show_all()
            newmenu.popup(None, None, None, button, self.window.time())
            
            return True
            #box.add(show_devices, True, True, 0)
            show_devices.run()
        else:
            show_devices.destroy()


if __name__ == "__main__":
    mw = MonitoringHandler()
    Gtk.main()
