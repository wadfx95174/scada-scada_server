from multiprocessing import Process, Pipe
import ctypes
import socket, ssl
from threading import Thread 
import json
import jwt, hashlib
import time
import uuid
# from enum import Enum
import modbus_tk.defines as cst
import addr_defines

# JWT from TTAS(CP)
jwtFromTTAS = b''
# JWT from TTAS(TVM)
jwtFromTTAS_TVM = b''

# thread class
class ServerThread(Thread):

    def __init__(self, conn, addr, pipe1):
        Thread.__init__(self)
        self._conn = conn
        self._addr = addr
        self._pipe1 = pipe1
        
    def run(self):
        while True:
            global jwtFromTTAS_TVM
            dataFromTTAS = self._conn.recv(2048)
            print ("From", self._addr, ": " + dataFromTTAS.decode("utf-8"))
            self._conn.sendall("Control program got TTAS's Token.".encode("utf-8"))
            jwtFromTTAS_TVM = dataFromTTAS
            # self._pipe1.send(dataFromTTAS)
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
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr_defines.CP_IP, addr_defines.CP_PORT))
        sock.listen(5)
        print ("Server start at: %s:%s" %(addr_defines.CP_IP, addr_defines.CP_PORT))
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
    
# connect TTAS and send data to TTAS
def connectTTAS():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load certificate file
    context.load_verify_locations("./key/certificate.pem")
    # prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    # open socket and connect TTAS
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((addr_defines.TTAS_IP, addr_defines.TTAS_PORT))
            dic = {}
            dic["hostname"] = socket.gethostname()
            dic["mac_addr"] = uuid.UUID(int = uuid.getnode()).hex[-12:]
            dic["TVM_ip"] = addr_defines.TVM_IP
            dic["TVM_port"] = addr_defines.TVM_PORT
            dic["converter_ip"] = addr_defines.CONVERTER_IP
            dic["converter_port"] = addr_defines.CONVERTER_PORT
            dic["slave_id"] = 1
            dic["function_code"] = cst.READ_INPUT_REGISTERS
            dic["starting_address"] = 0
            dic["quantity_of_x"] = 3

            sock.sendall(bytes(json.dumps(dic), encoding="utf-8"))
            dataFromTTAS = sock.recv(2048)
            global jwtFromTTAS
            jwtFromTTAS = dataFromTTAS
            # try:
            #     # verify jwt via signature and decode it via rsa's public key
            #     decodedData = jwt.decode(dataFromTTAS, jwt.decode(dataFromTTAS, verify=False)["public_key"].encode("utf-8")
            #         , issuer=AddrType.TTASIP.value, audience=AddrType.IP.value, algorithm='RS256')
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

# connect TVM and send data to Raspberry 
def connectTVM(pipe2):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((addr_defines.TVM_IP, addr_defines.TVM_PORT))
            sock.sendall(jwtFromTTAS)
            # wait for feadback of TVM
            dataFromTVM = sock.recv(1024).decode("utf-8")
            
            while True:
                # Token from control program is legal
                if dataFromTVM == "Legal":
                    print("Token from control program is legal.")
                    
                    # wait for TVM send Device's data with Token
                    responseFromTVM = sock.recv(2048).decode("utf-8")
                    s = responseFromTVM.split("+++++")
                    jsonFromDevice = json.loads(s[1])
                    print(responseFromTVM)
                    jwtFromTVM = s[0]
                    print(jwtFromTVM)
                    print(jsonFromDevice)
                    print("Humidity :", format(float(jsonFromDevice[0])/float(100),'.2f'))
                    print("Temperature (Celsius) :", format(float(jsonFromDevice[1])/float(100),'.2f'))
                    print("Temperature (Fahrenheit) :", format(float(jsonFromDevice[2])/float(100),'.2f'))

                    # if jwtFromTTAS == jwtFromTVM:
                    #     audienceIP = addr_defines.CP_IP
                    # elif pipe2.recv() == jwtFromTVM:
                    #     audienceIP = addr_defines.TVM_IP
                    # else:
                    #     sock.sendall("Your Token is illegal.".encode("utf-8"))
                    #     break

                    try:
                        decodedData = jwt.decode(jwtFromTVM, jwt.decode(jwtFromTVM, verify=False)["public_key"].encode("utf-8")
                            , issuer=addr_defines.TTAS_IP, audience=addr_defines.TVM_IP, algorithm='RS256')
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

                # Token from control program is illegal, resend verification information to TTAS
                else:
                    print("Token from control program is illegal.")
                    connectTTAS()
                    sock.sendall(jwtFromTTAS)
                    dataFromTVM = sock.recv(1024).decode("utf-8")

            sock.sendall("close".encode("utf-8"))
            pipe2.close()

        except socket.error:
            print ("Connect error")

def clientMain(pipe2):
    while True:
        # connectTTAS()
        try:
            try:
                # global jwtFromTTAS
                # verify jwt via signature and decode it via rsa's public key
                decodedData = jwt.decode(jwtFromTTAS, jwt.decode(jwtFromTTAS, verify=False)["public_key"].encode("utf-8")
                    , issuer=addr_defines.TTAS_IP, audience=addr_defines.CP_IP, algorithm='RS256')
                connectTVM(pipe2)
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
            
            time.sleep(6)
        except KeyboardInterrupt:
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