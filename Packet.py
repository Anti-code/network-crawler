class DefaultPacket(object):
    def __init__(self):
        self.no = 0
        self.time = ""
        self.source_ip = ""
        self.source_mac = ""
        self.source_port = ""
        self.destination_ip = ""
        self.destination_mac = ""
        self.destination_port = ""
        self.summary = ""
        self.whole = ""

    def __str__(self):
        return str(self.no)

    def toList(self):
        return [str(self.no),
                str(self.time),
                self.source_ip,
                self.source_mac,
                str(self.source_port),
                self.destination_ip,
                self.destination_mac,
                str(self.destination_port),
                self.summary]
