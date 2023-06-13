import hashlib
from typing import BinaryIO

_BUFFER_SIZE = 32768


def hash_file_sha256(file: BinaryIO) -> str:
    sha256 = hashlib.sha256()
    while True:
        data = file.read(_BUFFER_SIZE)
        if not data:
            break
        sha256.update(data)
    return sha256.hexdigest()
