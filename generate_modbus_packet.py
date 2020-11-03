from scapy impotr *

class Modbus(Packet):
    name = "Modbus/tcp"
    fields_desc = [
        # ShortField("Transaction Identifier", int('00001', 16)),
        # ShortField("Protocol Identifier", int('0000', 16)),
        # ShortField("Length", int('5', 16)),
        ShortField("Transaction Identifier", 1),
        ShortField("Protocol Identifier", 0),
        ShortField("Length", 6),
        XByteField("Unit Identifier", int('1', 16)),
        XByteField("Function Code", int('4', 16)),
        # BitFieldLenField("Byte Count", None, 6),
        # FieldListField("Register Value", [], [5346, 2640, 7952]),
        # BitFieldLenField("Byte Count", 2, 8),
        # FieldListField("Register Value", [0x0000], ShortField('', 0x0000)),
        ShortField("register", int('0000', 16)),
        ShortField("Word Count", int('0003', 16))
    ]
    # fields_desc = [
    #     XByteField("Function Code", 0x04),
    #     BitFieldLenField("byteCount", None, 8, count_of="registerVal", adjust=lambda x: x*2),
    #     FieldListField("registerVal", [0x0000], ShortField('', 0x0000), count_from=lambda pkt: pkt.byteCount)
    # ]

# set Ethernet fields
# src_mac = "00:25:90:bb:b3:e6"
# dst_mac = "00:90:e8:79:3e:9d"
src_mac = "00:0d:e0:81:3c:a5"
dst_mac = "f4:28:53:1c:49:8d"

# set IP fields
# src_ip = "172.16.100.12"
# dst_ip = "172.16.100.46"
src_ip = "172.16.100.100"
dst_ip = "172.16.100.200"
ihl = 5
length = 52
ttl = 60
proto = 'tcp'
ip_id = 8

# set TCP fields
sport = 502
dport = 5000
seq = int('d519a1b7', 16)
ack = int('02d762b3', 16)
tcp_flags = 'PA'
window = 4096
dataofs = 5
urgptr = 0

def generatePacket():
    return Ether(src=src_mac, dst=dst_mac)/\
        IP(src=src_ip, dst=dst_ip, ihl=ihl, len=length, ttl=ttl, proto=proto, chksum=None)/\
        TCP(sport=sport, dport=dport, flags=tcp_flags, window=window, dataofs=dataofs, chksum=None, urgptr=urgptr)/\
        Modbus()

pkt = generatePacket()
print(pkt.display())
# print(ls(IP))
# print(ls(TCP))
# print(ls(Modbus))
sendp(pkt)
