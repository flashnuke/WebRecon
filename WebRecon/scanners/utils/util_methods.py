import hashlib


def get_filehash(path: str) -> str:
    return hashlib.md5(open(path, 'rb').read()).hexdigest()
