import uuid, socket
mac_addr = uuid.UUID(int = uuid.getnode()).hex[-12:]
print (mac_addr) #Mac address here
hostname = socket.gethostname()
print (hostname)
