from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

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