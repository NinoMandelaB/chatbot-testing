import os
from cryptography.fernet import Fernet

# Generate this once locally: print(Fernet.generate_key().decode())
# Then set it as RAILWAY env var: DATA_ENCRYPTION_KEY
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY")
if not DATA_ENCRYPTION_KEY:
    raise RuntimeError("DATA_ENCRYPTION_KEY env var not set")

fernet = Fernet(DATA_ENCRYPTION_KEY.encode())


def encrypt_str(value: str) -> bytes:
    if value is None:
        return None
    return fernet.encrypt(value.encode("utf-8"))


def decrypt_str(value: bytes) -> str:
    if value is None:
        return None
    return fernet.decrypt(value).decode("utf-8")


def encrypt_int(value: int) -> bytes:
    if value is None:
        return None
    return fernet.encrypt(str(value).encode("utf-8"))


def decrypt_int(value: bytes) -> int:
    if value is None:
        return None
    return int(fernet.decrypt(value).decode("utf-8"))
