from multiprocessing import Process, Pipe
import ctypes
# import socketClient, socketServer
import socket, ssl
from threading import Thread 
import json
import jwt, hashlib
import time
import uuid
from enum import Enum
import modbus_tk.defines as cst

# JWT from TBAS
jwtFromTBAS = b''
# JWT from TBAS by Pi
jwtFromTBASbyPi = b''

# address enumerate
class AddrType(Enum):
    CP_IP_eth0 = "140.116.164.141"
    CP_IP_eth1 = "192.168.1.101"
    CP_PORT = 8001
    TBAS_IP = "192.168.1.100"
    TBAS_PORT = 8001
    PI_IP = "192.168.1.102"
    PI_PORT = 8001
    CONVERTER_IP = "192.168.2.105"
    CONVERTER_PORT = "502"

# thread class
class ServerThread(Thread):

    def __init__(self, conn, addr, pipe1):
        Thread.__init__(self)
        self._conn = conn
        self._addr = addr
        self._pipe1 = pipe1
        
    def run(self):
        while True:
            # global jwtFromTBASbyPi
            dataFromTBAS = self._conn.recv(2048)
            print ("From", self._addr, ": " + dataFromTBAS.decode("utf-8"))
            self._conn.sendall("Control program got TBAS's Token.".encode("utf-8"))
            self._pipe1.send(dataFromTBAS)
            print(self._addr, "disconnect!")
            self._conn.close()
            break

def serverMain(pipe1):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load private key and certificate file
    context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
    # prohibit the use of TLSv1.0, TLgSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    # open, bind, listen socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((AddrType.CP_IP_eth1.value, AddrType.CP_PORT.value))
        sock.listen(5)
        print ("Server start at: %s:%s" %(AddrType.CP_IP_eth1.value, AddrType.CP_PORT.value))
        print ("Wait for connection...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr, pipe1)
                    newThread.start()
                    newThread.join()
                    
                except KeyboardInterrupt:
                    break

# choice enumerate
class Choice(Enum):
    ONE = "1"
    TWO = "2"
    THREE = "3"
    
# connect TBAS and send data to TBAS
def connectTBAS():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load certificate file
    context.load_verify_locations("./key/certificate.pem")
    # prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    # open socket and connect TBAS
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((AddrType.TBAS_IP.value, AddrType.TBAS_PORT.value))
            dic = {}
            # dic["account"] = input("Please enter your account : ")
            # dic["passwd"] = input("Please enter your password : ")
            # dic["account"] = "a"
            # dic["passwd"] = "123"
            dic["hostname"] = socket.gethostname()
            dic["mac_addr"] = uuid.UUID(int = uuid.getnode()).hex[-12:]
            dic["Pi_ip"] = AddrType.PI_IP.value
            dic["Pi_port"] = AddrType.PI_PORT.value
            dic["converter_ip"] = AddrType.CONVERTER_IP.value
            dic["converter_port"] = AddrType.CONVERTER_PORT.value
            dic["slave_id"] = 1
            dic["function_code"] = cst.READ_INPUT_REGISTERS
            dic["starting_address"] = 0
            dic["quantity_of_x"] = 3

            sock.sendall(bytes(json.dumps(dic), encoding="utf-8"))
            dataFromTBAS = sock.recv(2048)
            global jwtFromTBAS
            jwtFromTBAS = dataFromTBAS
            # try:
            #     # verify jwt via signature and decode it via rsa's public key
            #     decodedData = jwt.decode(dataFromTBAS, jwt.decode(dataFromTBAS, verify=False)["public_key"].encode("utf-8")
            #         , issuer=AddrType.TBASIP.value, audience=AddrType.IP.value, algorithm='RS256')
            #     print(decodedData)
            # except jwt.InvalidSignatureError:
            #     print("Signature verification failed.")
            # except jwt.DecodeError:
            #     print("DecodeError")
            # except jwt.ExpiredSignatureError:
            #     print("Signature has expired.")
            # except jwt.InvalidIssuerError:
            #     print("Issue is error.")
            # except jwt.InvalidAudienceError:
            #     print("Audience is error.")

            sock.sendall("close".encode("utf-8"))

        except socket.error:
            print ("Connect error")

# connect Raspberry Pi and send data to Raspberry 
def connectRaspberryPi(pipe2):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((AddrType.PI_IP.value, AddrType.PI_PORT.value))
            sock.sendall(jwtFromTBAS)
            # wait for feadback of Pi
            dataFromPi = sock.recv(1024).decode("utf-8")
            
            while True:
                # Token from control program is legal
                if dataFromPi == "Legal":
                    print("Token from control program is legal.")
                    
                    # wait for Pi send Device's data with Token
                    jwtFromPi = sock.recv(2048)

                    # print(jwtFromPi)
                    if jwtFromTBAS == jwtFromPi:
                        audienceIP = AddrType.CP_IP_eth0.value
                    elif pipe2.recv() == jwtFromPi:
                        audienceIP = AddrType.PI_IP.value
                    else:
                        sock.sendall("Your Token is illegal.".encode("utf-8"))
                        break

                    try:
                        decodedData = jwt.decode(jwtFromPi, jwt.decode(jwtFromPi, verify=False)["public_key"].encode("utf-8")
                            , issuer=AddrType.TBAS_IP.value, audience=audienceIP, algorithm='RS256')
                        print(decodedData)
                    except jwt.InvalidSignatureError:
                        print("Signature verification failed.")
                        sock.sendall("Signature verification failed.".encode("utf-8"))
                    except jwt.DecodeError:
                        print("Decode Error.")
                        sock.sendall("Decode Error.".encode("utf-8"))
                    except jwt.ExpiredSignatureError:
                        print("Signature has expired.")
                        sock.sendall("Signature has expired.".encode("utf-8"))
                    except jwt.InvalidAudienceError:
                        print("Audience is error.")
                        sock.sendall("Audience is error.".encode("utf-8"))
                    except jwt.InvalidIssuerError:
                        print("Issue is error.")
                        sock.sendall("Issue is error.".encode("utf-8"))
                    except jwt.InvalidIssuedAtError:
                        print("The time of the Token was issued which is error.")
                        sock.sendall("The time of the Token was issued which is error.".encode("utf-8"))
                # Token from control program is illegal, resend verification information to TBAS
                else:
                    print("Token from control program is illegal.")
                    connectTBAS()
                    sock.sendall(jwtFromTBAS)
                    dataFromPi = sock.recv(1024).decode("utf-8")

            sock.sendall("close".encode("utf-8"))
            pipe2.close()

        except socket.error:
            print ("Connect error")

def clientMain(pipe2):
    while True:
        # print("Please choice what do you want.")
        # choice = input("(1)Send data to TBAS. (2)Send data to Raspberry Pi. (3)Close. : ")
        # if choice == Choice.ONE.value:
        #     # startTime = time.time()
        connectTBAS()
        # elif choice == Choice.TWO.value and jwtFromTBAS:
        connectRaspberryPi(pipe2)
        # elif choice == Choice.THREE.value:
        break

def main():
    (pipe1, pipe2) = Pipe()
    server = Process(target=serverMain, args=(pipe1, ))

    server.start()
    clientMain(pipe2)

    pipe1.close()

    server.join()

if __name__ == '__main__':
    main()