from multiprocessing import Process, Pipe
import socket, ssl, uuid
from threading import Thread 
import json, jwt
import time
import addr_defines
import netfilterqueue
from scapy.all import *

# JWT from TTAS(CP)
jwtFromTTAS_CP = b''
# JWT from TTAS(TVM)
jwtFromTTAS_TVM = b''

# CP information
dic = {}
dic = {
  'hostname': socket.gethostname(),
  'mac_addr': uuid.UUID(int = uuid.getnode()).hex[-12:],
  'ip': addr_defines.TVM_IP,
  'port': addr_defines.TVM_PORT
}
# sensor information
# sensorDic = {}
# sensorDic = {
#   'converter_ip': addr_defines.CONVERTER_IP,
#   'converter_port': addr_defines.CONVERTER_PORT,
#   'slave_id': 1,
#   'function_code': cst.READ_INPUT_REGISTERS,
#   'starting_address': 0,
#   'quantity_of_x': 3
# }

# netfilterqueue class
class NFQueue:
    def __init__(self, pipe):
        self._pipe = pipe
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self._context.load_verify_locations("./key/certificate.pem")
        self._context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
        self._sensorDict = {}

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
        if pkt.haslayer(Raw) and int.from_bytes(pkt[Raw].load[6:7], byteorder='big') == 4:
            
            load = pkt[Raw].load
            print(pkt.show())
            self._sensorDict = {
                'CPAddr': pkt[IP].src,
                'CPPort': pkt[TCP].sport,
                'converter_ip': pkt[IP].dst,
                'converter_port': pkt[TCP].dport,
                'transaction_id': int.from_bytes(load[0:2], byteorder='big'),
                'slave_id': int.from_bytes(load[6:7], byteorder='big'),
                'function_code': int.from_bytes(load[7:8], byteorder='big'),
                'starting_address': int.from_bytes(load[8:10], byteorder='big'),
                'quantity_of_x': int.from_bytes(load[10:12], byteorder='big')
            }

            print(self._sensorDict)
            
            # send request to TVM
            clientMain(self._pipe, self._context, self._sensorDict)
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
            # print ("From", self._addr, ": " + dataFromTTAS.decode("utf-8"))
            self._conn.sendall("Control program got TTAS's Token.".encode("utf-8"))
            self._pipe.send(dataFromTTAS)
            # print(self._addr, "disconnect!")
            self._conn.close()
            break

def serverMain(pipe):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load private key and certificate file
    context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
    # prohibit the use of TLSv1.0, TLgSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    # open, bind, listen socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        # avoid continuous port occupation
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr_defines.CP_IP, addr_defines.CP_PORT))
        sock.listen(5)
        # print ("Server start at: %s:%s" %(addr_defines.CP_IP, addr_defines.CP_PORT))
        # print ("Wait for connection...")

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
    # prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
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

def clientMain(pipe, context, sensorDic):
    # connect TVM and send request to TVM 
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((addr_defines.TVM_IP, addr_defines.TVM_PORT))
            while True:
                try:
                    try:
                        global jwtFromTTAS_CP
                        # verify jwt via signature and decode it via rsa's public key
                        decodedData = jwt.decode(jwtFromTTAS_CP, jwt.decode(jwtFromTTAS_CP, verify=False)["public_key"].encode("utf-8")
                            , issuer=addr_defines.TTAS_IP, audience=addr_defines.CP_IP, algorithm='RS256')
                        
                        sock.sendall((jwtFromTTAS_CP.decode("utf-8") + "+++++" + json.dumps(sensorDic)).encode("utf-8"))
                        # wait for feadback of TVM
                        feadbackFromTVM = sock.recv(1024).decode("utf-8")
                        
                        while True:
                            # Token from control program is legal
                            if feadbackFromTVM == "Legal":
                                # print("Token from control program is legal.")
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
                                responseFromTVM = sock.recv(2048).decode("utf-8")
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
                                        print("Humidity :", format(float(dataFromDevice[0])/float(100),'.2f'))
                                        print("Temperature (Celsius) :", format(float(dataFromDevice[1])/float(100),'.2f'))
                                        print("Temperature (Fahrenheit) :", format(float(dataFromDevice[2])/float(100),'.2f'))
                                        sock.sendall("close".encode("utf-8"))
                                        break
                                    except jwt.InvalidSignatureError:
                                        # print("Signature verification failed.")
                                        sock.sendall("Signature verification failed.".encode("utf-8"))
                                    except jwt.DecodeError:
                                        # print("Decode Error.")
                                        sock.sendall("Decode Error.".encode("utf-8"))
                                    except jwt.ExpiredSignatureError:
                                        # print("Signature has expired.")
                                        sock.sendall("Signature has expired.".encode("utf-8"))
                                    except jwt.InvalidAudienceError:
                                        # print("Audience is error.")
                                        sock.sendall("Audience is error.".encode("utf-8"))
                                    except jwt.InvalidIssuerError:
                                        # print("Issue is error.")
                                        sock.sendall("Issue is error.".encode("utf-8"))
                                    except jwt.InvalidIssuedAtError:
                                        # print("The time of the Token was issued which is error.")
                                        sock.sendall("The time of the Token was issued which is error.".encode("utf-8"))
                                else:
                                    sock.sendall("Token from TVM is illegal.".encode("utf-8"))
                                    
                            # Token from control program is illegal, resend verification information to TTAS
                            else:
                                # print(feadbackFromTVM)
                                connectTTAS()
                                sock.sendall((jwtFromTTAS_CP.decode("utf-8") + "+++++" + json.dumps(sensorDic)).encode("utf-8"))
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
                    
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    sock.sendall("close".encode("utf-8"))
                    sock.close()
                    break
            sock.sendall("close".encode("utf-8"))
            sock.close()
        except socket.error:
            print ("Connect error")
    
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
                    global sensorDic
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
    # startTime = time.time()
    # onlySSLSocket()
    # endTime = time.time()
    # print(endTime - startTime)
    '''
    other
    '''
    (clientMainPipe, serverPipe) = Pipe()
    server = Process(target=serverMain, args=(serverPipe, ))
    server.start()

    startTime = time.time()

    nfqueue = NFQueue(clientMainPipe)
    nfqueue.start()

    serverPipe.close()
    clientMainPipe.close()

    endTime = time.time()
    print(endTime - startTime)

    server.join()

if __name__ == '__main__':
    main()