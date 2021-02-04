from scapy.all import *

class Modbus_TCP(Packet):
    name = "Modbus/TCP"
    fields_desc = [
        XShortField("TransactionIdentifier", 0x0001),
        XShortField("ProtocolIdentifier", 0x0000),
        ShortField("Length", 0x0000),
        XByteField("UnitIdentifier", 0x00)
    ]

class Modbus(Packet):
    name = "Modbus"
    fields_desc = [
        XByteField("FunctionCode", 0x04),
        BitFieldLenField("ByteCount", 0x00, 8, count_of="RegisterValue", adjust=lambda pkt, x: x*2),
        FieldListField("RegisterValue", [], ShortField('', 0x0000), count_from=lambda pkt: pkt.ByteCount)
    ]
    # fields_desc = [
    #     XByteField("FunctionCode", 0x04),
    #     BitFieldLenField("ByteCount", None, 8),
    #     FieldListField("RegisterValue", [], ShortField('', 0x0000))
    # ]
class ModbusError(Packet):
    name = "Exception"
    fields_desc = [
        XByteField("FunctionCode", 0x84),
        ShortField("ExceptionCode", 0x06)
    ]


# set Ethernet fields
EthernetDict = {
    'dst_mac' : "00:25:90:bb:b3:e6",
    'src_mac' : "00:90:e8:79:3e:9d",
    # 'src_mac' : "00:0d:e0:81:3c:a5",
    # 'dst_mac' : "f4:28:53:1c:49:8d",
    # 'src_mac': "dc:a6:32:91:53:d6",
    # 'dst_mac': "ac:22:0b:8c:72:a2"
}

# set IP fields
IPDict = {
    'src_ip' : "172.16.100.12",
    'dst_ip' : "172.16.100.46",
    # 'src_ip' : "172.16.100.100",
    # 'dst_ip' : "172.16.100.200",
    # 'src_ip' : "192.168.2.6",
    # 'dst_ip' : "192.168.2.2",
    'ihl' : 5,
    'length' : 55,
    'ttl' : 60,
    'proto' : 'tcp',
    'ip_id' : 8
}


# set TCP fields
TCPDict = {
    'sport' : 502,
    'dport' : 5000,
    'seq' : 0,
    'ack' : 0,
    'tcp_flags' : 'PA',
    'window' : 4096,
    'dataofs' : 5,
    'urgptr' : 0
}

def generatePacket(modbus_TCP, modbus):
    return Ether(src=EthernetDict['src_mac'], dst=EthernetDict['dst_mac'])/\
        IP(src=IPDict['src_ip'], dst=IPDict['dst_ip'], ihl=IPDict['ihl']\
            , len=IPDict['length'], ttl=IPDict['ttl'], proto=IPDict['proto'], chksum=None)/\
        TCP(sport=TCPDict['sport'], dport=TCPDict['dport'], seq=TCPDict['seq'], ack=TCPDict['ack']\
            , flags=TCPDict['tcp_flags'], window=TCPDict['window'], dataofs=TCPDict['dataofs']\
            , chksum=None, urgptr=TCPDict['urgptr'])/\
        modbus_TCP/modbus

# print(pkt.display())
# sendp(pkt)
