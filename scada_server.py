from multiprocessing import Process, Pipe
import socket, ssl, uuid
from threading import Thread
import json, jwt
import time
import modbus_tk.defines as cst
import defines
import logging

logging.basicConfig(
    filename="./log/logfile.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# JWT from TTAS(SCADA Server)for TVM
jwtFromTTAS_SS = b''
# JWT from TTAS(TVM)
jwtFromTTAS_TVM = b''

# JWT from TTAS(SCADA Server) for BEMS
jwtFromTTAS_SS_BEMS = b''
# JWT from TTAS(BEMS)
jwtFromTTAS_BEMS = b''

# for prevent DoS attack
sequence_num = str(1)
# for prevent Dos attack from BEMS
sequence_num_BEMS = str(1)

# SCADA Server information for TVM
dic_TVM = {}
# SCADA Server information for BEMS
dic_BEMS = {}

dic_TVM = {
  # 'hostname': socket.gethostname(),
  'hostname': "SCADA",
  'mac_addr': uuid.UUID(int = uuid.getnode()).hex[-12:],
  'ip': defines.TVM_IP,
  'port': defines.TVM_PORT,
  'dst_hostname': defines.TVM_hostname,
  'dst_mac_addr': defines.TVM_MAC_ADDR
}

dic_BEMS = {
  #'hostname': socket.gethostname(),
  'hostname': "SCADA",
  'mac_addr': uuid.UUID(int = uuid.getnode()).hex[-12:],
  'ip': defines.BEMS_IP,
  'port': defines.BEMS_PORT,
  'dst_hostname': defines.BEMS_hostname,
  'dst_mac_addr': defines.BEMS_MAC_ADDR
}

# sensor information
sensorDic = {}
sensorDic = {
  'converter_ip': defines.CONVERTER_IP,
  'converter_port': defines.CONVERTER_PORT,
  'slave_id': 1,
  'function_code': cst.READ_INPUT_REGISTERS,
  'starting_address': 0,
  'quantity_of_x': 3
}

# thread class
class ServerThread(Thread):

    def __init__(self, conn, addr, pipe):
        Thread.__init__(self)
        self._conn = conn
        self._addr = addr
        self._pipe = pipe

    def run(self):
        global jwtFromTTAS_BEMS, jwtFromTTAS_TVM
        sleepTime = 1
        while True:
            try:
                messageFromTTASorBEMS = self._conn.recv(2048)
            except:
                logging.info("The connection has something wrong.")
                break

            # if BEMS send "close", then close connection
            if messageFromTTASorBEMS == "close":
                self._conn.close()
                break

            # connect by TTAS
            if self._addr[0] == defines.TTAS_IP:
                if jwt.decode(messageFromTTASorBEMS, verify=False)["aud"] == defines.BEMS_IP:
                    jwtFromTTAS_BEMS = messageFromTTASorBEMS
                else:
                    self._pipe.send(messageFromTTASorBEMS)
                self._conn.sendall("SCADA server got TTAS's Token.".encode("utf-8"))
                self._conn.close()

            # connect by BEMS
            elif self._addr[0] == defines.BEMS_IP:
                splitMessageFromBEMS = messageFromTTASorBEMS.decode("utf-8").split("++")
                jwtFromBEMS = splitMessageFromBEMS[0].encode("utf-8")
                command = splitMessageFromBEMS[1]

                if jwtFromTTAS_BEMS == jwtFromBEMS:
                    try:
                        decodedData_BEMS = jwt.decode(jwtFromBEMS, jwt.decode(jwtFromBEMS, verify=False)["public_key"]
                            , issuer=defines.TTAS_IP, audience=self._addr[0], algorithm='ES256')
                        baseTime = decodedData_BEMS['exp'] - decodedData_BEMS['iat']
                        if int(splitMessageFromBEMS[2]) / baseTime > 2:
                            logging.critical("The usage frequency of the Token from SCADA Server is too high, maybe it is a DoS attack.")
                            self._conn.sendall("too often".encode("utf-8"))
                            if sleepTime == 1:
                                self._conn.shutdown(self._sock.SHUT_RDWR)
                                self._conn.close()
                                break
                            time.sleep(sleepTime)
                            sleepTime *= 4
                        else:
                            self._conn.sendall("Legal".encode("utf-8"))
                            sleepTime = 1
                            global jwtFromTTAS_SS_BEMS, sequence_num_BEMS

                            while True:
                                try:
                                    decodedData = jwt.decode(jwtFromTTAS_SS_BEMS, jwt.decode(jwtFromTTAS_SS_BEMS
                                        , verify=False)["public_key"], issuer=defines.TTAS_IP
                                        , audience=defines.SS_IP, algorithm='ES256')

                                    break
                                except jwt.InvalidSignatureError:
                                    logging.info("Token's signature from TTAS (apply from BEMS) is invalid.")
                                    connectTTAS("BEMS")
                                except jwt.DecodeError:
                                    logging.info("Token from TTAS (apply from BEMS) is invalid.")
                                    connectTTAS("BEMS")
                                except jwt.ExpiredSignatureError:
                                    logging.info("Token from TTAS (apply from BEMS) hss expired.")
                                    connectTTAS("BEMS")
                                except jwt.InvalidIssuerError:
                                    logging.info("Token's issuer from TTAS (apply from BEMS) is invalid.")
                                    connectTTAS("BEMS")
                                except jwt.InvalidAudienceError:
                                    logging.info("Token's audience from TTAS (apply from BEMS) is invalid.")
                                    connectTTAS("BEMS")

                            self._conn.sendall((jwtFromTTAS_SS_BEMS.decode("utf-8") + "++" + "Response from SCADA Server.++" + sequence_num_BEMS).encode("utf-8"))
                            sequence_num_BEMS = str(int(sequence_num_BEMS) + 1)

                            feadbackFromBEMS = self._conn.recv(1024).decode("utf-8")

                            while True:
                                if feadbackFromBEMS == "close":
                                    break
                                elif feadbackFromBEMS == "too often":
                                    self._conn.shutdown(self._sock.SHUT_RDWR)
                                    self._conn.close()
                                    break
                                else:
                                    connectTTAS("BEMS")
                                    self._conn.sendall((jwtFromTTAS_SS_BEMS.decode("utf-8") + "++" + "Response from SCADA Server.++" + sequence_num_BEMS).encode("utf-8"))
                                    # add 1 after using it once
                                    sequence_num += str(int(sequence_num) + 1)
                                    feadbackFromSS = self._conn.recv(1024).decode("utf-8")

                    except jwt.InvalidSignatureError:
                        logging.info("Token's signature from BEMS is invalid.")
                        self._conn.sendall("Signature verification failed.".encode("utf-8"))
                    except jwt.DecodeError:
                        logging.info("Token from BEMS can not be decoded.")
                        self._conn.sendall("Decode Error.".encode("utf-8"))
                    except jwt.ExpiredSignatureError:
                        logging.info("Token from BEMS has expired.")
                        self._conn.sendall("Signature has expired.".encode("utf-8"))
                    except jwt.InvalidAudienceError:
                        logging.info("Token's audience from BEMS is invalid.")
                        self._conn.sendall("Audience is error.".encode("utf-8"))
                    except jwt.InvalidIssuerError:
                        logging.info("Token's issuer from BEMS is invalid.")
                        self._conn.sendall("Issue is error.".encode("utf-8"))
                    except jwt.InvalidIssuedAtError:
                        logging.info("Token's issue time from BEMS is invalid.")
                        self._conn.sendall("The time of the Token was issued which is error.".encode("utf-8"))

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
        sock.bind((defines.SS_IP, defines.SS_PORT))
        sock.listen(5)

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr, pipe)
                    newThread.start()
                except Exception as e:
                    logging.warning("Someone try to connect SCADA Server, but has something wrong.")
                except KeyboardInterrupt:
                    break

# connect TTAS and send information to TTAS (for apply Token)
def connectTTAS(dst):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    # prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((defines.TTAS_IP, defines.TTAS_PORT))


            if dst == "TVM":
                global dic_TVM, jwtFromTTAS_SS, sequence_num
                sock.sendall(bytes(json.dumps(dic_TVM), encoding="utf-8"))
                messageFromTTAS = sock.recv(2048)
                jwtFromTTAS_SS = messageFromTTAS
                sequence_num = str(1)
            elif dst == "BEMS":
                global dic_BEMS, jwtFromTTAS_SS_BEMS, sequence_num_BEMS
                sock.sendall(bytes(json.dumps(dic_BEMS), encoding="utf-8"))
                messageFromTTAS = sock.recv(2048)
                jwtFromTTAS_SS_BEMS = messageFromTTAS
                sequence_num_BEMS = str(1)

            sock.sendall("close".encode("utf-8"))
            sock.close()

        except socket.error:
            logging.info("Connect TTAS error.")

def clientMain(pipe):
    # connect TVM and send request to TVM
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((defines.TVM_IP, defines.TVM_PORT))
            breakMark = False
            while True:
                try:
                    try:
                        global jwtFromTTAS_SS, sensorDic, sequence_num
                        # verify jwt via signature and decode it via ECDSA's public key
                        decodedData_SS = jwt.decode(jwtFromTTAS_SS, jwt.decode(jwtFromTTAS_SS, verify=False)["public_key"]
                            , issuer=defines.TTAS_IP, audience=defines.SS_IP, algorithm='ES256')


                        sock.sendall((jwtFromTTAS_SS.decode("utf-8") + "++" + json.dumps(sensorDic) + "++" + sequence_num).encode("utf-8"))
                        # add 1 after using it once
                        sequence_num = str(int(sequence_num) + 1)
                        # wait for feadback of TVM
                        feadbackFromTVM = sock.recv(1024).decode("utf-8")
                        sleepTime = 1
                        while True:

                            # Token from SCADA server is legal
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
                                responseFromTVM = sock.recv(2048).decode("utf-8")
                                splitResponseFromTVM = responseFromTVM.split("++")
                                jwtFromTVM = splitResponseFromTVM[0].encode("utf-8")
                                dataFromDevice = json.loads(splitResponseFromTVM[1])

                                global jwtFromTTAS_TVM
                                # check if there is still data in the pipe
                                if pipe.poll(0.05):
                                    jwtFromTTAS_TVM = pipe.recv()
                                # check "JWT from TTAS" and "JWT from TVM" is same or not
                                if jwtFromTTAS_TVM == jwtFromTVM:
                                    try:
                                        decodedData = jwt.decode(jwtFromTVM, jwt.decode(jwtFromTVM, verify=False)["public_key"]
                                            , issuer=defines.TTAS_IP, audience=defines.TVM_IP, algorithm='ES256')

                                        baseTime = decodedData['exp'] - decodedData['iat']

                                        # the usage frequency of the Token from TVM is too high
                                        if int(splitResponseFromTVM[2]) / baseTime > 500:
                                            logging.critical("The usage frequency of the Token from TVM is too high, maybe it is a DoS attack.")
                                            sock.sendall("too often".encode("utf-8"))
                                            if sleepTime == 1:
                                                sock.close()
                                                breakMark = True
                                            time.sleep(sleepTime)
                                            sleepTime *= 4
                                            break
                                        else:
                                            # the information from device is abnormal
                                            sleepTime = 1
                                            if dataFromDevice[0] > 80000 or dataFromDevice[0] < 2000 \
                                                or dataFromDevice[1] > 4000 or dataFromDevice[1] < 1000 \
                                                or dataFromDevice[2] > 10400 or dataFromDevice[2] < 5000 \
                                                or dataFromDevice == "error":
                                                logging.warning("The information from " + decodedData['hostname'] + " (IP : " + decodedData['aud'] + ") is abnormal.")
                                            else:
                                                print ("Humidity :", format(float(dataFromDevice[0])/float(100),'.2f'))
                                                print ("Temperature (Celsius) :", format(float(dataFromDevice[1])/float(100),'.2f'))
                                                print ("Temperature (Fahrenheit) :", format(float(dataFromDevice[2])/float(100),'.2f'))
                                                sock.sendall("close".encode("utf-8"))
                                                break
                                    except jwt.InvalidSignatureError:
                                        logging.info("Token's signature from TVM is invalid.")
                                        sock.sendall("Signature verification failed.".encode("utf-8"))
                                    except jwt.DecodeError:
                                        logging.info("Token from TVM can not be decoded.")
                                        sock.sendall("Decode Error.".encode("utf-8"))
                                    except jwt.ExpiredSignatureError:
                                        logging.info("Token from TVM has expired.")
                                        sock.sendall("Signature has expired.".encode("utf-8"))
                                    except jwt.InvalidAudienceError:
                                        logging.info("Token's audience from TVM is invalid.")
                                        sock.sendall("Audience is error.".encode("utf-8"))
                                    except jwt.InvalidIssuerError:
                                        logging.info("Token's issuer from TVM is invalid.")
                                        sock.sendall("Issue is error.".encode("utf-8"))
                                    except jwt.InvalidIssuedAtError:
                                        logging.info("Token's issue time form TVM is invalid.")
                                        sock.sendall("The time of the Token was issued which is error.".encode("utf-8"))
                                else:
                                    logging.info("Token from TVM is invalid.")
                                    sock.sendall("Token from TVM is illegal.".encode("utf-8"))

                            # Token from SCADA server is illegal, resend verification information to TTAS
                            elif feadbackFromTVM == "too often":
                                logging.critical("The request from SCADA Server is too often.")
                                sock.close()
                                break
                            else:
                                connectTTAS("TVM")
                                try:
                                    sock.sendall((jwtFromTTAS_SS.decode("utf-8") + "++" + json.dumps(sensorDic) + "++" + sequence_num).encode("utf-8"))
                                    # add 1 after using it once
                                    sequence_num = str(int(sequence_num) + 1)
                                    feadbackFromTVM = sock.recv(1024).decode("utf-8")
                                except socket.error:
                                    logging.warning("Send request to TVM error, mayby it is a DoS attack.")

                    except jwt.InvalidSignatureError:
                        logging.info("Token's signature from TTAS (apply from SCADA server) is invalid.")
                        connectTTAS("TVM")
                    except jwt.DecodeError:
                        logging.info("Token from TTAS (apply from SCADA server) can not be decoded.")
                        connectTTAS("TVM")
                    except jwt.ExpiredSignatureError:
                        logging.info("Token from TTAS (apply from SCADA server) has expired.")
                        connectTTAS("TVM")
                    except jwt.InvalidIssuerError:
                        logging.info("Token's issuer from TTAS (apply from SCADA server) is invalid.")
                        connectTTAS("TVM")
                    except jwt.InvalidAudienceError:
                        logging.info("Token's audience from TTAS (apply from SCADA server) is invalid.")
                        connectTTAS("TVM")

                    time.sleep(1)
                except KeyboardInterrupt:
                    sock.sendall("close".encode("utf-8"))
                    sock.close()
                    break

                if breakMark:
                    break
        except socket.error:
            logging.info("Connect TVM error.")

def onlySSLSocket():
    # connect TVM and send request to TVM 
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((defines.TVM_IP, defines.TVM_PORT))
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
            logging.info("Connect TVM error (without Token).")
def main():
    '''
    Only SSL socket
    '''
    # onlySSLSocket()
    '''
    other
    '''
    connectTTAS("TVM")
    (clientMainPipe, serverPipe) = Pipe()
    server = Process(target=serverMain, args=(serverPipe, ))

    server.start()

    clientMain(clientMainPipe)

    clientMainPipe.close()
    serverPipe.close()
    try:
        server.join()
    except KeyboardInterrupt:
        print ("\nend")


if __name__ == '__main__':
    main()
