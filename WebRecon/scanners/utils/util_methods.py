import hashlib

from typing import Union


def get_filehash(path: str) -> Union[str, None]:
    return hashlib.md5(open(path, 'rb').read()).hexdigest() if path else ""
