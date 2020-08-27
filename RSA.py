from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# generate private/public key pair
key = rsa.generate_private_key(
    backend=default_backend(), 
    public_exponent=65537,
    key_size=2048
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