from modbus_tk import modbus_tcp
import modbus_tk
import netfilterqueue
from scapy.all import *
import struct

def main():
    print('start')
    queue = netfilterqueue.NetfilterQueue()
    queue = bind(0, processPacket)
    try:
        queue.run()
    except KeyboardInterrupt:
        print("end")
    queue.unbind()

def processPacket(packet):
    pkt = IP(packet.get_payload())
    # print(pkt.show())
    if pkt.haslayer(Raw):
        sensorAddr = pkt.getlayer(IP).dst
        sensorPort = pkt.getlayer(IP).dport
        print(sensorAddr)
        print(sensorPort)
        load = pkt(Raw).load
        print("load", load)
        transID = int.from_bytes(load[0:2], byteorder='big')
        slaveID = int.from_bytes(load[6:7], byteorder='big')
        funcCode = int.from_bytes(load[7:8], byteorder='big')
        startAddr = int.from_bytes(load[8:10], byteorder='big')
        wordCount = int.from_bytes(load[10:12], byteorder='big')
        print("transID", transID)
        print("slaveID", slaveID)
        print("funcCode", funcCode)
        print("startAddr", startAddr)
        print("wordCount", wordCount)

        master = modbus_tcp.TcpMaster(sensorAddr, sensorPort)
        try:
            data = master.execute(slave=slaveID, function_code=funcCode, starting_address=startAddr, quantity_of_x=wordCount)
            print("Humidity :", format(float(data[0])/float(100),'.2f'))
            print("Temperature (Celsius) :", format(float(data[1])/float(100),'.2f'))
            print("Temperature (Fahrenheit) :", format(float(data[2])/float(100),'.2f'))
        except modbus_tk.modbus.ModbusError as exc:
            print("%s- Code=%d", exc, exc.get_exception_code())
        except modbus_tcp.ModbusInvalidMbapError as exc:
            print(exc)

        packet.setpayload(bytes(pkt))

    packet.accept()

if __name__ == '__main__':
    main()