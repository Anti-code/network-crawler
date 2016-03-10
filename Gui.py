import tkinter as tk
from tkinter import ttk
from scapy.all import *
from io import StringIO
from scapy.sendrecv import sniff
from threading import Thread
class Gui(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.geometry("1000x600")
        self.button = ttk.Button(text="Start", command=self.start)
        self.button.grid()
        #self.progress = ttk.Progressbar(self, orient="horizontal", length=200, mode="determinate")
        #self.progress.pack()
        self.tree = ttk.Treeview(self)
        self.tree["columns"]=('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Information')
        self.tree["show"]='headings'
        self.tree.column("No", width=75 )
        self.tree.column("Time", width=75)
        self.tree.column("Source", width=75)
        self.tree.column("Destination", width=75)
        self.tree.column("Protocol", width=75)
        self.tree.column("Length", width=75)
        self.tree.column("Information", width=150)
        self.tree.heading("No", text="No")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.heading("Information", text="Information")
        self.tree.grid(sticky=tk.NSEW, padx = 300)
        self.sniff_list =[]
        #self.mac_vendors = {x.split("\t")[0]:x.split("\t")[1] for x in open('newlook.txt').readlines()}
        self.packet_no = 0
        self.running = False


    def start(self):
        """Enable scanning by setting the global flag to True."""
        if self.running == False:
            self.checkForGroupUpdates()
            self.button["text"] = "Stop"
            self.running = True
        else:
            self.button["text"] = "Start"
            self.running = False

    def showOnTree(self):
        #self.tree.insert("" , self.packet_no, text=data.name, values=(self.packet_no, data.time, data.hwsrc, data.hwdst, 'ARP', 123, data.summary()))
        self.packet_no +=1
        self.after(50, self.checkForGroupUpdates)


if __name__ == "__main__":
    app=Gui()
    app.mainloop()
