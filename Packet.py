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
    # paket str metoduyla kullanıldığında paket numarasını döndürür  p = DefaultPacket, str(p) -> p.no
    def __str__(self):
        return str(self.no)

    # tabloda göstermek istediğimiz özellikleri bir liste haline getirdik
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
