from multiprocessing import Process, Pipe
import ctypes
# import socketClient, socketServer
import socket, ssl
from threading import Thread 
import json
import jwt, hashlib
import time
from enum import Enum
import modbus_tk.defines as cst

# JWT from TBAS
jwtFromTBAS = b''
# JWT from TBAS by Pi
jwtFromTBASbyPi = b''

# address enumerate
class AddrType(Enum):
    IP = "192.168.87.1"
    PORT = 8001
    TBASIP = "192.168.87.128"
    TBASPORT = 8001
    PI1IP = "192.168.87.134"
    PI1PORT = 8001
    CONVERTER_IP = "192.168.163.150"
    CONVERTER_PORT = "502"

# thread class
class ServerThread(Thread):

    def __init__(self, conn, addr, pipe1):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.pipe1 = pipe1
        
    def run(self):
        while True:
            # global jwtFromTBASbyPi
            dataFromTBAS = self.conn.recv(2048)
            print ("From", self.addr, ": " + dataFromTBAS.decode("utf-8"))
            self.conn.sendall("Control program got TBAS's Token.".encode("utf-8"))
            self.pipe1.send(dataFromTBAS)
            print(self.addr, "disconnect!")
            self.conn.close()
            break

def serverMain(pipe1):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load private key and certificate file
    context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
    # prohibit the use of TLSv1.0, TLgSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    # open, bind, listen socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((AddrType.IP.value, AddrType.PORT.value))
        sock.listen(5)
        print ("Server start at: %s:%s" %(AddrType.IP.value, AddrType.PORT.value))
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
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as ssock:
        try:
            ssock.connect((AddrType.TBASIP.value, AddrType.TBASPORT.value))
            dic = {}
            # dic["account"] = input("Please enter your account : ")
            # dic["passwd"] = input("Please enter your password : ")
            dic["account"] = "a"
            dic["passwd"] = "123"
            dic["ip"] = AddrType.PI1IP.value
            dic["port"] = AddrType.PI1PORT.value
            dic["converter_ip"] = AddrType.CONVERTER_IP.value
            dic["converter_port"] = AddrType.CONVERTER_PORT.value
            dic["slave_id"] = 1
            dic["function_code"] = cst.READ_INPUT_REGISTERS
            dic["starting_address"] = 0
            dic["quantity_of_x "] = 3

            ssock.sendall(bytes(json.dumps(dic), encoding="utf-8"))
            dataFromTBAS = ssock.recv(2048)
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

            ssock.sendall("close".encode("utf-8"))

        except socket.error:
            print ("Connect error")

# connect Raspberry Pi and send data to Raspberry 
def connectRaspberryPi(pipe2):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as ssock:
        try:
            ssock.connect((AddrType.PI1IP.value, AddrType.PI1PORT.value))
            ssock.sendall(jwtFromTBAS)
            # wait for feadback of Pi
            dataFromPi = ssock.recv(1024).decode("utf-8")
            
            while True:
                # Token from control program is legal
                if dataFromPi == "Legal":
                    print("Token from control program is legal.")
                    
                    # wait for Pi send Device's data with Token
                    jwtFromPi = ssock.recv(2048)

                    # print(jwtFromPi)
                    try:
                        if jwtFromTBAS == jwtFromPi:
                            decodedData = jwt.decode(jwtFromPi, jwt.decode(jwtFromPi, verify=False)["public_key"].encode("utf-8")
                                , issuer=AddrType.TBASIP.value, audience=AddrType.IP.value, algorithm='RS256')
                            print(decodedData)
                            break
                        else:
                            decodedData = jwt.decode(jwtFromPi, jwt.decode(jwtFromPi, verify=False)["public_key"].encode("utf-8")
                                , issuer=AddrType.TBASIP.value, audience=AddrType.PI1IP.value, algorithm='RS256')
                            if pipe2.recv() == jwtFromPi:
                                print(decodedData)
                                break
                            else:
                                ssock.sendall("Your Token is illegal.".encode("utf-8"))
                    except jwt.InvalidSignatureError:
                        print("Signature verification failed.")
                        ssock.sendall("Signature verification failed.".encode("utf-8"))
                    except jwt.DecodeError:
                        print("Decode Error.")
                        ssock.sendall("Decode Error.".encode("utf-8"))
                    except jwt.ExpiredSignatureError:
                        print("Signature has expired.")
                        ssock.sendall("Signature has expired.".encode("utf-8"))
                    except jwt.InvalidAudienceError:
                        print("Audience is error.")
                        ssock.sendall("Audience is error.".encode("utf-8"))
                    except jwt.InvalidIssuerError:
                        print("Issue is error.")
                        ssock.sendall("Issue is error.".encode("utf-8"))
                    except jwt.InvalidIssuedAtError:
                        print("The time of the Token was issued which is error.")
                        ssock.sendall("The time of the Token was issued which is error.".encode("utf-8"))
                # Token from control program is illegal, resend verification information to TBAS
                else:
                    print("Token from control program is illegal.")
                    connectTBAS()
                    ssock.sendall(jwtFromTBAS)
                    dataFromPi = ssock.recv(1024).decode("utf-8")

            ssock.sendall("close".encode("utf-8"))
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