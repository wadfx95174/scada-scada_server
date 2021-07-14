from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import jwt
import time
# generate private/public key pair
key = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
)
# get private key from key
private_key  = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
# get public key from key
public_key = key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
# decode to string
private_key_str = private_key.decode('utf-8')
public_key_str = public_key.decode('utf-8')
print('Private key = ')
print(private_key_str)
print('Public key = ')
print(public_key_str)


a = jwt.encode({"iss": "172.16.100.234", "iat": int(time.time()), "exp": int(time.time()) + 100, "aud": "172.16.100.233", "public_key": public_key_str}, private_key_str, algorithm="ES256")
b = jwt.decode(a, public_key_str, issuer="172.16.100.234"
    , audience="172.16.100.233", algorithm='ES256')
print(a)
print(b)
