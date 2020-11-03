from modbus_tk import modbus_tcp
import modbus_tk
import netfilterqueue
from scapy.all import *

class NFQueue:
    def __init__(self, test):
        self._test = test
    
    def start(self):
        print("start")
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, self.processPacket)
        try:
            queue.run()
        except KeyboardInterrupt:
            print("end")
        queue.unbind()
    
    def processPacket(self, packet):
        pkt = IP(packet.get_payload())
        if pkt.haslayer(Raw) and int.from_bytes(pkt[Raw].load[6:7], byteorder='big') == 1:
            print(pkt.show())
            CPAddr = pkt[IP].src
            CPPort = pkt[TCP].sport
            sensorAddr = pkt[IP].dst
            sensorPort = pkt[TCP].dport
            load = pkt[Raw].load
            transID = int.from_bytes(load[0:2], byteorder='big')
            slaveID = int.from_bytes(load[6:7], byteorder='big')
            funcCode = int.from_bytes(load[7:8], byteorder='big')
            startAddr = int.from_bytes(load[8:10], byteorder='big')
            wordCount = int.from_bytes(load[10:12], byteorder='big')
            print("CPAddr: ", CPAddr)
            print("CPPort: ", CPPort)
            print("sensorAddr: ", sensorAddr)
            print("sensorPort: ", sensorPort)
            print("transID: ", transID)
            print("slaveID: ", slaveID)
            print("funcCode: ", funcCode)
            print("startAddr: ", startAddr)
            print("wordCount: ", wordCount)
        pakcet.accept()


def main():
    print('start')
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, processPacket)
    try:
        queue.run()
    except KeyboardInterrupt:
        print("end")
    queue.unbind()

def processPacket(packet):
    pkt = IP(packet.get_payload())
    # print(pkt.show())
    if pkt.haslayer(Raw):
        print(pkt.show())
        CPAddr = pkt[IP].src
        CPPort = pkt[TCP].sport
        sensorAddr = pkt[IP].dst
        sensorPort = pkt[TCP].dport
        load = pkt[Raw].load
        transID = int.from_bytes(load[0:2], byteorder='big')
        slaveID = int.from_bytes(load[6:7], byteorder='big')
        funcCode = int.from_bytes(load[7:8], byteorder='big')
        startAddr = int.from_bytes(load[8:10], byteorder='big')
        wordCount = int.from_bytes(load[10:12], byteorder='big')
        print("CPAddr: ", CPAddr)
        print("CPPort: ", CPPort)
        print("sensorAddr: ", sensorAddr)
        print("sensorPort: ", sensorPort)
        print("transID: ", transID)
        print("slaveID: ", slaveID)
        print("funcCode: ", funcCode)
        print("startAddr: ", startAddr)
        print("wordCount: ", wordCount)

    packet.accept()

if __name__ == '__main__':
    # main()
    t = NFQueue("test word")
    t.start()