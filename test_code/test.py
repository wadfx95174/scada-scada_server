import json 

dic = {}
dic["hostname"] = "socket.gethostname()"
dic["mac_addr"] = "hk"
dic["CP_ip"] = "addr_defines.CP_IP"
dic["CP_port"] = "addr_defines.CP_PORT"

a = json.dumps(dic)
b = json.dumps(dic)

ab = a + '+++++' + b

print(ab)

s = ab.split('+++++')

c = json.loads(s[0])
d = json.loads(s[1])

print(c['hostname'])
print(d)