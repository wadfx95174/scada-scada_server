import hashlib

sha3_51 = hashlib.sha3_512()
sha3_51.update(("123" + "456").encode('utf-8'))
hashValue = sha3_51.hexdigest()
print(hashValue)