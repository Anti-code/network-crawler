import gi

gi.require_version("Gtk", "3.0")
from threading import Thread
from gi.repository import Gtk
from multiprocessing import Process
from sniff import PacketSniffer
class MonitoringHandler():
    def __init__(self):
        self.builder = Gtk.Builder()
        self.builder.add_from_file("monitoring.glade")
        self.builder.connect_signals(self)


        self.liststore = Gtk.ListStore(str, str, str, str, str, str, str, str, str)
        self.content_table = self.builder.get_object("content_table")
        

        no_column = Gtk.TreeViewColumn("No", Gtk.CellRendererText(), text=0)
        self.content_table.append_column(no_column)

        time_column = Gtk.TreeViewColumn("Time", Gtk.CellRendererText(), text=1)
        self.content_table.append_column(time_column)
        sip_column = Gtk.TreeViewColumn("Source IP", Gtk.CellRendererText(), text=2)
        self.content_table.append_column(sip_column)
        smac_column = Gtk.TreeViewColumn("Source MAC", Gtk.CellRendererText(), text=3)
        self.content_table.append_column(smac_column)
        sport_column = Gtk.TreeViewColumn("Source Port", Gtk.CellRendererText(), text=4)
        self.content_table.append_column(sport_column)
        dip_column = Gtk.TreeViewColumn("Destination IP", Gtk.CellRendererText(), text=5)
        self.content_table.append_column(dip_column)
        dmac_column = Gtk.TreeViewColumn("Destination MAC", Gtk.CellRendererText(), text=6)
        self.content_table.append_column(dmac_column)
        dport_column = Gtk.TreeViewColumn("Destination Port", Gtk.CellRendererText(), text=7)
        self.content_table.append_column(dport_column)
        sum_column = Gtk.TreeViewColumn("Summary", Gtk.CellRendererText(), text=8)
        self.content_table.append_column(sum_column)
        self.content_table.set_model(self.liststore)
        self.ps = PacketSniffer()
       	self.ps.cookie = False
        self.window = self.builder.get_object("window")
        self.window.connect("delete-event", Gtk.main_quit)
        self.window.show()
    def append(self):
        while self.ps.cookie:
            packet = self.ps.run().__next__()
            print([packet["no"], packet["time"], packet["ips"],packet["macs"], packet["ports"], packet["ipd"], packet["macd"], packet["portd"], packet["sum"]])
        
            if len(self.liststore) < 15:
                self.liststore.insert(0, [packet["no"], packet["time"], packet["ips"],packet["macs"], str(packet["ports"]), packet["ipd"], packet["macd"], str(packet["portd"]), packet["sum"]])
            else:
                self.liststore.remove(self.liststore[14].iter)   
                self.liststore.insert(0, [packet["no"], packet["time"], packet["ips"],packet["macs"], str(packet["ports"]), packet["ipd"], packet["macd"], str(packet["portd"]), packet["sum"]])

    def onSwitch(self, Switch, active):
        if Switch.get_active():
        	self.ps.cookie = True
        	Thread(target = self.append, daemon = True).start()
        else:
        	self.ps.cookie = False
        	print("Scan Off")

    def onSearch(self, Entry):
        print(Entry.get_text())

    def onProtocolSelected(self):
        print("hi")


if __name__ == "__main__":
    mw = MonitoringHandler()
    Gtk.main()
