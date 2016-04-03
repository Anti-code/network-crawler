import gi

gi.require_version("Gtk", "3.0")
from threading import Thread
from gi.repository import Gtk
from multiprocessing import Process
from sniff import PacketSniffer
from collections import OrderedDict

class MonitoringHandler(object):
    def __init__(self):
        self.builder = Gtk.Builder()
        self.builder.add_from_file("main_window.glade") 
        self.builder.connect_signals(self)

        self.ps = PacketSniffer(interface="wlan0")

        self.content_table = self.builder.get_object("content_table")

        columns = ["No", "Time", "Source IP", "Source MAC", "Source Port", "Destination IP", "Destination MAC",
                   "Destination Port", "Summary"]
        for no, column in enumerate(columns):
            self.content_table.append_column(Gtk.TreeViewColumn(column, Gtk.CellRendererText(), text=no))

        self.packet_list = []
        """protocols = ["All", "ARP", "IP", "TCP", "UDP", "HTTP", "DNS"]
        self.protocols = self.builder.get_object("protocols_box")
        self.protocols.set_entry_text_column(0)
        self.protocols.connect("changed", self.reFilter)
        for protocol in protocols:
            self.protocols.append_text(protocol)
        self.protocols.set_active(0)"""
        
        self.liststore = Gtk.ListStore(str, str, str, str, str, str, str, str, str)
        self.filter = self.liststore.filter_new()
        self.filter.set_visible_func(self.onSearch)
        self.content_table.set_model(self.filter)

        self.filter_field = self.builder.get_object("filter_field")
        self.filter_field.connect("changed", self.reFilter)

        self.window = self.builder.get_object("window")
        self.window.set_size_request(800, 500)
        self.window.connect("delete-event", Gtk.main_quit)

        self.window.show()

    def reFilter(self, entry):
        self.filter.refilter()

    def onSearch(self, model, treeiter, data= None):
        for column in range(self.content_table.get_n_columns()+1):
                value = self.liststore.get_value(treeiter, column).lower()
                if self.filter_field.get_text() in value :
                    return True

    def onContentSelected(self, treeview, treeiter, path):
        #self.liststore[treeiter][:]
        dialog = Gtk.MessageDialog(self.window, 0, Gtk.MessageType.INFO,Gtk.ButtonsType.OK)
        dialog.format_secondary_text(self.packet_list[int(self.liststore[treeiter][0])])
        dialog.run()
        dialog.destroy()

    def append(self):
        while self.ps.cookie:
            packet = self.ps.run()
            self.packet_list.append(packet.whole)
            self.liststore.insert(0, packet.toList())
            self.content_table.set_cursor(0)

    def onSwitch(self, switch, _):
        if switch.get_active():
            self.ps.cookie = True
            Thread(target=self.append, daemon=True).start() 
        else:
            self.ps.cookie = False


if __name__ == "__main__":
    mw = MonitoringHandler()
    Gtk.main()
