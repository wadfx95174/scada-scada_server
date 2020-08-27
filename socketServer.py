import socket, ssl
from threading import Thread 
import json
import jwt, hashlib
import time
from enum import Enum
# JWT from TBAS
jwtFromTBAS = b''

# address enumerate
class AddrType(Enum):
    IP = "192.168.87.1"
    PORT = 8001
    TBASIP = "192.168.87.132"
    TBASPORT = 8001
    PI1IP = "192.168.87.134"
    PI1PORT = 8001

# thread class
class ServerThread(Thread):

    def __init__(self, conn, addr):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        
    def run(self):
        while True:
            global jwtFromTBAS
            dataFromTBAS = self.conn.recv(2048)
            print ("From", self.addr, ": " + dataFromTBAS.decode("utf-8"))
            self.conn.sendall("Control program got TBAS's Token.".encode("utf-8"))
            print(self.addr, "disconnect!")
            self.conn.close()
            break

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load private key and certificate file
    context.load_cert_chain("./certificate.pem", "./privkey.pem")
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
                    newThread = ServerThread(conn, addr)
                    newThread.start()
                    newThread.join()
                    
                except KeyboardInterrupt:
                    break

# if __name__ == "__main__":
#     main()