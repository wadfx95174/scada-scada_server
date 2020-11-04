from scapy.all import *

class Modbus_TCP(Packet):
    name = "Modbus/TCP"
    fields_desc = [
        XShortField("TransactionIdentifier", 0x0001),
        XShortField("ProtocolIdentifier", 0x0000),
        ShortField("Length", None),
        XByteField("UnitIdentifier", 0x01),

        # BitFieldLenField("Byte Count", 2, 8),
        # FieldListField("Register Value", [0x0000], ShortField('', 0x0000)),
        # ShortField("register", int('0000', 16)),
        # ShortField("Word Count", int('0003', 16))
    ]

class Modbus(Packet):
    name = "Modbus"
    # fields_desc = [
    #     XByteField("FunctionCode", 0x04),
    #     BitFieldLenField("ByteCount", None, 8, count_of="RegisterValue", adjust=lambda pkt, x: x*2),
    #     FieldListField("RegisterValue", [], ShortField('', 0x0000), count_from=lambda pkt: pkt.ByteCount)
    # ]
    fields_desc = [
        XByteField("FunctionCode", 0x04),
        BitFieldLenField("ByteCount", None, 8),
        FieldListField("RegisterValue", [], ShortField('', 0x0000))
    ]

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
length = 55
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

modbus_TCP = Modbus_TCP()
modbus = Modbus()

modbus.RegisterValue.append(0x14e7)
modbus.RegisterValue.append(0x0a4f)
modbus.RegisterValue.append(0x1f0e)
modbus_TCP.Length = 0x0009
modbus.ByteCount = 0x06

def generatePacket():
    return Ether(src=src_mac, dst=dst_mac)/\
        IP(src=src_ip, dst=dst_ip, ihl=ihl, len=length, ttl=ttl, proto=proto, chksum=None)/\
        TCP(sport=sport, dport=dport, flags=tcp_flags, window=window, dataofs=dataofs, chksum=None, urgptr=urgptr)/\
        modbus_TCP/modbus

pkt = generatePacket()
print(pkt.display())
# print(ls(IP))
# print(ls(TCP))
# print(ls(Modbus))
sendp(pkt)
