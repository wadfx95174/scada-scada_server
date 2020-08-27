import socket, ssl
import json
from enum import Enum
import jwt, hashlib
import time

# address enumerate
class AddrType(Enum):
    IP = "192.168.87.1"
    TBASIP = "192.168.87.132"
    TBASPORT = 8001
    PI1IP = "192.168.87.134"
    PI1PORT = 8001

# choice enumerate
class Choice(Enum):
    ONE = "1"
    TWO = "2"
    THREE = "3"

# JWT from TBAS
jwtFromTBAS = b''
# JWT from TBAS by Pi
# jwtFromTBASbyPi = b''

# connect TBAS and send data to TBAS
def connectTBAS():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load certificate file
    context.load_verify_locations("./certificate.pem")
    # prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    # open socket and connect TBAS
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as ssock:
        try:
            ssock.connect((AddrType.TBASIP.value, AddrType.TBASPORT.value))
            # interval = time.time() - startTime
            # print(interval)
            dic = {}
            dic["account"] = input("Please enter your account : ")
            dic["passwd"] = input("Please enter your password : ")
            dic["ip"] = AddrType.PI1IP.value
            dic["port"] = AddrType.PI1PORT.value

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
def connectRaspberryPi():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./certificate.pem")
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
                    try:
                        decodedData = jwt.decode(jwtFromPi, jwt.decode(jwtFromPi, verify=False)["public_key"].encode("utf-8")
                            , issuer=AddrType.TBASIP.value, audience=AddrType.PI1IP.value, algorithm='RS256')
                        print(decodedData)
                        ssock.sendall("close".encode("utf-8"))
                        break
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
                    # break
                # Token from control program is illegal, resend verification information to TBAS
                else:
                    print("Token from control program is illegal.")
                    connectTBAS()
                    ssock.sendall(jwtFromTBAS)
                    dataFromPi = ssock.recv(1024).decode("utf-8")
                    
            ssock.sendall("close".encode("utf-8"))

        except socket.error:
            print ("Connect error")

def main():
    while True:
        print("Please choice what do you want.")
        choice = input("(1)Send data to TBAS. (2)Send data to Raspberry Pi. (3)Close. : ")
        if choice == Choice.ONE.value:
            # startTime = time.time()
            connectTBAS()
        elif choice == Choice.TWO.value and jwtFromTBAS:
            connectRaspberryPi()
        elif choice == Choice.THREE.value:
            break

# if __name__ == "__main__":
#     main()
