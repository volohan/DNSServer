from DNSServer import UnprocessedPackage


class DNSPackage:
    def __init__(self, data):
        self._data = data

        self.ID = self._data[:2]

        self.QR = self._data[2] >> 7
        self.Opcode = (self._data[2] & 120) >> 3
        self.AA = (self._data[2] & 4) >> 2
        self.TC = (self._data[2] & 2) >> 1
        self.RD = self._data[2] & 1
        self.RA = self._data[3] >> 7
        self.Z = (self._data[3] & 112) >> 4
        self.RCODE = self._data[3] & 15

        self.QDCOUNT = int.from_bytes(self._data[4:6], 'big')
        self.ANCOUNT = int.from_bytes(self._data[6:8], 'big')
        self.NSCOUNT = int.from_bytes(self._data[8:10], 'big')
        self.ARCOUNT = int.from_bytes(self._data[10:12], 'big')

        i = 12
        self.questions = []
        for _ in range(self.QDCOUNT):
            name, i = self.parse_name(i)

            type = int.from_bytes(self._data[i: i + 2], 'big')
            qclass = int.from_bytes(self._data[i + 2: i + 4], 'big')

            self.questions.append((name, type, qclass))

            i += 4

        self.answers = []
        for _ in range(self.ANCOUNT):
            i = self.parse_RR(self.answers, i)

        self.authoritys = []
        for _ in range(self.NSCOUNT):
            i = self.parse_RR(self.authoritys, i)

        self.additionals = []
        for _ in range(self.ARCOUNT):
            i = self.parse_RR(self.additionals, i)

    def parse_RR(self, list, i):
        name, i = self.parse_name(i)

        type = int.from_bytes(self._data[i: i + 2], 'big')

        qclass = int.from_bytes(self._data[i + 2: i + 4], 'big')
        TTL = int.from_bytes(self._data[i + 4: i + 8], 'big')
        offset = int.from_bytes(self._data[i + 8: i + 10], 'big')

        i += 10

        if type == 1:
            RDATA = ""
            RDLENGTH = 4
            for shift in range(RDLENGTH):
                RDATA += str(self._data[i + shift]) + "."
            RDATA = RDATA[:-1]
        elif type == 28:
            RDATA = ""
            RDLENGTH = 16
            for shift in range(0, RDLENGTH, 2):
                RDATA += hex(self._data[i + shift])[2:].zfill(2) + hex(
                    self._data[i + shift + 1])[2:].zfill(2) + ":"
            RDATA = RDATA[:-1]
        elif type == 12 or type == 2:
            RDATA, _ = self.parse_name(i)
            RDLENGTH = len(RDATA) + 1
        else:
            RDLENGTH = offset
            RDATA = self._data[i: i + RDLENGTH]

        i += offset
        list.append((name, type, qclass, TTL, RDLENGTH, RDATA))
        return i

    def parse_name(self, i):
        name = ""
        if self._data[i] != 0:
            ty = self._data[i] >> 6
            if ty == 0:
                le = self._data[i] & 63
                next_part = self.parse_name(i + le + 1)
                name = self._data[i + 1:i + le + 1].decode('ascii') + '.' + \
                       next_part[0]
                i = next_part[1]
            elif ty == 3:
                j = int.from_bytes(
                    (self._data[i] & 63).to_bytes(1, byteorder="big") +
                    self._data[i + 1:i + 2], 'big')
                name = self.parse_name(j)[0]
                i += 2
            else:
                raise UnprocessedPackage
        else:
            i += 1
        return name, i

    def update_data(self):
        self._data = b''
        self._data += self.ID
        self._data += ((self.QR << 7) + (self.Opcode << 3) + (self.AA << 2) + (
                self.TC << 1) + self.RD).to_bytes(1, byteorder="big")
        self._data += ((self.RA << 7) + (self.Z << 4) + self.RCODE) \
            .to_bytes(1, byteorder="big")
        self._data += len(self.questions).to_bytes(2, byteorder="big")
        self._data += len(self.answers).to_bytes(2, byteorder="big")
        self._data += len(self.authoritys).to_bytes(2, byteorder="big")
        self._data += len(self.additionals).to_bytes(2, byteorder="big")

        for name, type, qclass in self.questions:
            self._data += b''.join(
                [len(dom).to_bytes(1, byteorder="big") + dom.encode("ascii")
                 for dom in name.split('.')])

            self._data += type.to_bytes(2, byteorder="big")
            self._data += qclass.to_bytes(2, byteorder="big")

        for name, type, qclass, TTL, RDLENGTH, RDATA in self.answers + self.authoritys + self.additionals:
            self.add_RR(name, type, qclass, TTL, RDLENGTH, RDATA)

    def add_RR(self, name, type, qclass, TTL, RDLENGTH, RDATA):
        self._data += b''.join(
            [len(dom).to_bytes(1, byteorder="big") + dom.encode("ascii")
             for dom in name.split('.')])

        self._data += type.to_bytes(2, byteorder="big")
        self._data += qclass.to_bytes(2, byteorder="big")
        self._data += TTL.to_bytes(4, byteorder="big")
        self._data += RDLENGTH.to_bytes(2, byteorder="big")
        if type == 1:
            self._data += b''.join(map(lambda x: bytes(x), list(
                map(lambda x: int(x).to_bytes(1, byteorder="big"),
                    RDATA.split('.')))))
        elif type == 28:
            for i in RDATA.split(':'):
                self._data += int(i[:2], 16).to_bytes(1, byteorder="big")
                self._data += int(i[2:], 16).to_bytes(1, byteorder="big")
        elif type == 12 or type == 2:
            self._data += b''.join(
                [len(dom).to_bytes(1, byteorder="big") + dom.encode("ascii")
                 for dom in RDATA.split('.')])
        else:
            self._data += RDATA

    def add_answer(self, name, type, qclass, TTL, RDATA):
        self.QR = 1
        if type == 1:
            RDLENGTH = 4
        elif type == 28:
            RDLENGTH = 16
        elif type == 12 or type == 2:
            RDLENGTH = len(RDATA) + 1
        else:
            raise UnprocessedPackage("add_answer")

        self.answers.append((name, type, qclass, TTL, RDLENGTH, RDATA))

    def get_data(self):
        self.update_data()
        return self._data


def parse_package(data):
    return DNSPackage(data)
