import os
import rsa
from utils import *
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from typing import Tuple, Union


class SSHRsa:

    def __init__(self, host_key_folderpath: str):
        self.path = host_key_folderpath
        self._current_hostkey = None  # type: Union[RSA.RsaKey, None]
        if not os.path.exists(self.path):
            raise IOError(f'Path {self.path} does not exist.')

        self.acceptable_hosts = []
        for f in os.listdir(host_key_folderpath):
            with open(f'{host_key_folderpath}/{f}', 'r') as key_file:
                self.acceptable_hosts.append(RSA.import_key(''.join(key_file.readlines()).encode()))

    # TODO: Fix to update host keys before write to allow for multiple clients adding new hosts without overwriting
    def __add_host_key(self, new_key: RSA.RsaKey, hostname: str) -> None:
        self.acceptable_hosts.append(new_key)
        with open(f'{self.path}/{hostname}', 'w') as key_file:
            key_file.writelines(new_key.export_key(format='OpenSSH').decode('utf-8'))

    def validate_hostkey(self, message: Union[bytes, str], signature: Union[bytes, str],
                         key: Tuple[int, int], hostname: str) -> bool:
        n = key[0]
        e = key[1]
        self._current_hostkey = RSA.construct((n, e), True)
        if self._current_hostkey not in self.acceptable_hosts:
            prompt = f"The authenticity of host can't be established.\nRSA key fingerprint is SHA256:{key}.\n" \
                     f"Are you sure you want to continue connection (Yes/no)?"
            if prompt_user(prompt):
                self.__add_host_key(self._current_hostkey, hostname)
                return True
            else:
                return False
        signing_key = PKCS1_v1_5.new(self._current_hostkey)
        digest = SHA1.new()
        digest.update(message)
        return signing_key.verify(digest, signature)

    def get_current_hostkey(self) -> RSA.RsaKey:
        return self._current_hostkey

    def set_hostkey(self, host_key: Union[str, bytes]) -> None:
        self._current_hostkey = RSA.import_key(host_key)
