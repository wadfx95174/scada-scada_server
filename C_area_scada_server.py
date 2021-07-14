from multiprocessing import Process
from multiprocessing import Pipe as multiprocess_Pipe
import socket, ssl, uuid
from threading import Thread
import json, jwt
import time
import addr_defines
import netfilterqueue
from scapy.all import *
import generate_modbus_packet

# JWT from TTAS(CP)
jwtFromTTAS_CP = b''
# JWT from TTAS(TVM)
jwtFromTTAS_TVM = b''

previousSlaveID = ''

# CP information
dic = {}
dic = {
  'hostname': socket.gethostname(),
  'mac_addr': uuid.UUID(int = uuid.getnode()).hex[-12:],
  'ip': addr_defines.TVM_IP,
  'port': addr_defines.TVM_PORT
}

# netfilterqueue class
class NFQueue:
    def __init__(self, pipe, sock):
        self._pipe = pipe
        self._sensorDict = {}
        self._sock = sock
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self._context.load_verify_locations("./key/certificate.pem")
        self._context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)

    def start(self):
        print ("start")
        try:
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, self.processPacket)
        except:
            print ("queue bind error")
        try:
            queue.run()
        except KeyboardInterrupt:
            print("end")
        queue.unbind()

    def processPacket(self, packet):
        pkt = IP(packet.get_payload())
        if pkt.haslayer(Raw) and int.from_bytes(pkt[Raw].load[6:7], byteorder='big') == 9:
            load = pkt[Raw].load
            global previousSlaveID
            self._sensorDict = {
                'CP_address': pkt[IP].src,
                'CP_port': pkt[TCP].sport,
                'converter_ip': pkt[IP].dst,
                'converter_port': pkt[TCP].dport,
                'seq': pkt[TCP].ack,
                'ack': pkt[TCP].seq + 12,
                'transaction_id': int.from_bytes(load[0:2], byteorder='big'),
                'slave_id': int.from_bytes(load[6:7], byteorder='big'),
                'function_code': int.from_bytes(load[7:8], byteorder='big'),
                'starting_address': int.from_bytes(load[8:10], byteorder='big'),
                'quantity_of_x': int.from_bytes(load[10:12], byteorder='big'),
            }
            # discard the origin packet
            packet.drop()
            # send request to TVM
            clientMain(self._sock, self._pipe, self._sensorDict, self._context)
        else:
            packet.accept()


# server thread class
class ServerThread(Thread):

    def __init__(self, conn, addr, pipe):
        Thread.__init__(self)
        self._conn = conn
        self._addr = addr
        self._pipe = pipe

    def run(self):
        while True:
            dataFromTTAS = self._conn.recv(2048)
            self._conn.sendall("Control program got TTAS's Token.".encode("utf-8"))
            self._pipe.send(dataFromTTAS)
            self._conn.close()
            break

def serverMain(pipe):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        # avoid continuous port occupation
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr_defines.CP_IP, addr_defines.CP_PORT))
        sock.listen(5)

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr, pipe)
                    newThread.start()
                    # newThread.join()

                except KeyboardInterrupt:
                    break

# connect TTAS and send data to TTAS
def connectTTAS():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((addr_defines.TTAS_IP, addr_defines.TTAS_PORT))

            global dic
            sock.sendall(bytes(json.dumps(dic), encoding="utf-8"))

            dataFromTTAS = sock.recv(2048)
            global jwtFromTTAS_CP

            jwtFromTTAS_CP = dataFromTTAS
            sock.sendall("close".encode("utf-8"))
            sock.close()

        except socket.error:
            print ("Connect error")

def clientMain(sock, pipe, sensorDict, context):
    try:
        global jwtFromTTAS_CP
        # verify jwt via signature and decode it via rsa's public key
        decodedData = jwt.decode(jwtFromTTAS_CP, jwt.decode(jwtFromTTAS_CP, verify=False)["public_key"].encode("utf-8")
            , issuer=addr_defines.TTAS_IP, audience=addr_defines.CP_IP, algorithm='RS256')

        sock.sendall((jwtFromTTAS_CP.decode("utf-8") + "+++++" + json.dumps(sensorDict)).encode("utf-8"))

        modbus_TCP = generate_modbus_packet.Modbus_TCP()
        modbus = generate_modbus_packet.Modbus()
        modbusError = generate_modbus_packet.ModbusError()

        modbus_TCP.TransactionIdentifier = sensorDict["transaction_id"]
        modbus_TCP.UnitIdentifier = sensorDict["slave_id"]
        generate_modbus_packet.TCPDict["dport"] = sensorDict["CP_port"]
        generate_modbus_packet.TCPDict["seq"] = sensorDict["seq"]
        generate_modbus_packet.TCPDict["ack"] = sensorDict["ack"]

        # wait for feadback of TVM
        feadbackFromTVM = sock.recv(1024).decode("utf-8")
        while True:
            # Token from control program is legal
            if feadbackFromTVM == "Legal":
                '''
                TVM without Token
                '''
                # responseFromTVM = sock.recv(2048).decode("utf-8")
                # dataFromDevice = json.loads(responseFromTVM)
                # print("Humidity :", format(float(dataFromDevice[0])/float(100),'.2f'))
                # print("Temperature (Celsius) :", format(float(dataFromDevice[1])/float(100),'.2f'))
                # print("Temperature (Fahrenheit) :", format(float(dataFromDevice[2])/float(100),'.2f'))
                # sock.sendall("close".encode("utf-8"))
                # break

                '''
                TVM with Token
                '''
                # wait for TVM send Device's data with Token
                responseFromTVM = sock.recv(4096).decode("utf-8")
                s = responseFromTVM.split("+++++")
                jwtFromTVM = s[0].encode("utf-8")
                dataFromDevice = json.loads(s[1])
                # check if there is still data in the pipe
                if pipe.poll(0.05):
                    global jwtFromTTAS_TVM
                    jwtFromTTAS_TVM = pipe.recv()
                if jwtFromTTAS_TVM == jwtFromTVM:
                    try:
                        decodedData = jwt.decode(jwtFromTVM, jwt.decode(jwtFromTVM, verify=False)["public_key"].encode("utf-8")
                            , issuer=addr_defines.TTAS_IP, audience=addr_defines.TVM_IP, algorithm='RS256')

                        if dataFromDevice != "error":
                            modbus.RegisterValue = dataFromDevice
                            modbus.ByteCount = len(modbus.RegisterValue) * 2
                            modbus_TCP.Length = modbus.ByteCount + 3
                            generate_modbus_packet.IPDict['length'] = modbus_TCP.Length + 46

                            pkt = generate_modbus_packet.generatePacket(modbus_TCP, modbus)
                        else:
                            modbus_TCP.Length = 3
                            generate_modbus_packet.IPDict['length'] = 49
                            pkt = generate_modbus_packet.generatePacket(modbus_TCP, modbusError)
                        sendp(pkt)

                        sock.sendall("close".encode("utf-8"))
                        break
                    except jwt.InvalidSignatureError:
                        sock.sendall("Signature verification failed.".encode("utf-8"))
                    except jwt.DecodeError:
                        sock.sendall("Decode Error.".encode("utf-8"))
                    except jwt.ExpiredSignatureError:
                        sock.sendall("Signature has expired.".encode("utf-8"))
                    except jwt.InvalidAudienceError:
                        sock.sendall("Audience is error.".encode("utf-8"))
                    except jwt.InvalidIssuerError:
                        sock.sendall("Issue is error.".encode("utf-8"))
                    except jwt.InvalidIssuedAtError:
                        sock.sendall("The time of the Token was issued which is error.".encode("utf-8"))
                else:
                    sock.sendall("Token from TVM is illegal.".encode("utf-8"))

            # Token from control program is illegal, resend verification information to TTAS
            else:
                connectTTAS()
                sock.sendall((jwtFromTTAS_CP.decode("utf-8") + "+++++" + json.dumps(sensorDict)).encode("utf-8"))
                feadbackFromTVM = sock.recv(1024).decode("utf-8")

    except jwt.InvalidSignatureError:
        connectTTAS()
    except jwt.DecodeError:
        connectTTAS()
    except jwt.ExpiredSignatureError:
        connectTTAS()
    except jwt.InvalidIssuerError:
        connectTTAS()
    except jwt.InvalidAudienceError:
        connectTTAS()

def onlySSLSocket():
    # connect TVM and send request to TVM 
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((addr_defines.TVM_IP, addr_defines.TVM_PORT))
            for i in range(10):
                try:
                    sensorDic = {}
                    sock.sendall(json.dumps(sensorDic).encode("utf-8"))
                    responseFromTVM = sock.recv(2048).decode("utf-8")
                    dataFromDevice = json.loads(responseFromTVM)
                    print("Humidity :", format(float(dataFromDevice[0])/float(100),'.2f'))
                    print("Temperature (Celsius) :", format(float(dataFromDevice[1])/float(100),'.2f'))
                    print("Temperature (Fahrenheit) :", format(float(dataFromDevice[2])/float(100),'.2f'))
                    sock.sendall("close".encode("utf-8"))

                    time.sleep(0.1)
                except KeyboardInterrupt:
                    sock.sendall("close".encode("utf-8"))
                    sock.close()
                    break
            sock.sendall("close".encode("utf-8"))
            sock.close()
        except socket.error:
            print ("Connect error")

def main():
    '''
    Only SSL socket
    '''
    # onlySSLSocket()
    '''
    other
    '''
    clientMainPipe, serverPipe = multiprocess_Pipe()
    server = Process(target=serverMain, args=(serverPipe, ))
    server.start()
    connectTTAS()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((addr_defines.TVM_IP, addr_defines.TVM_PORT))
            try:
                nfqueue = NFQueue(clientMainPipe, sock)
                nfqueue.start()
            except KeyboardInterrupt:
                sock.sendall("close".encode("utf-8"))
                sock.close()
                print("end")
        except socket.error as e:
            print (e)


    serverPipe.close()
    clientMainPipe.close()

    server.join()

if __name__ == '__main__':
    main()
