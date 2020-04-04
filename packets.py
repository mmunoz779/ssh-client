from ctypes import *
import os
import struct


class BinaryPacket:
    """
    uint32    packet_length
    byte      padding_length
    byte[n1]  payload; n1 = packet_length - padding_length - 1
    byte[n2]  random padding; n2 = padding_length
    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
    """

    def __init__(self, payload):
        pass


class KEXInitPacket:
    """
      byte         SSH_MSG_KEXINIT
      byte[16]     cookie (random bytes)
      name-list    kex_algorithms
      name-list    server_host_key_algorithms
      name-list    encryption_algorithms_client_to_server
      name-list    encryption_algorithms_server_to_client
      name-list    mac_algorithms_client_to_server
      name-list    mac_algorithms_server_to_client
      name-list    compression_algorithms_client_to_server
      name-list    compression_algorithms_server_to_client
      name-list    languages_client_to_server
      name-list    languages_server_to_client
      boolean      first_kex_packet_follows
      uint32       0 (reserved for future extension)
    """

    def __init__(self):
        # TODO: set to 1 and send guessed algorithm's packet
        self.SSH_MSG_KEXINIT = c_byte(0)  # type: c_byte
        self.cookie = (c_byte * 16)(*os.urandom(16))  # type: (c_byte * 16)
        self.kex_algorithms = 'diffie-hellman-group1-sha1, diffie-hellman-group14-sha1'  # type: str
        self.server_host_key_algorithms = 'ssh-dss, ssh-rsa, pgp-sign-rsa, pgp-sign-dss'
        self.encrpytion_algorithms_client_to_server = '3des-cbc'
        self.encrpytion_algorithms_server_to_client = '3des-cbc'
        self.mac_algorithms_client_to_server = 'hmac-sha1'
        self.mac_algorithms_server_to_client = 'hmac-sha1'
        self.compression_algorithms_client_to_server = 'none'
        self.compression_algorithms_server_to_client = 'none'
        self.languages_client_to_server = ''

    def asNamelist(self, namelist: str) -> c_uint32:
        # Remove any spaces
        namelist = ','.join([name.strip() for name in namelist.split(',')])
        namelist = (c_uint32 * len(namelist))(*create_string_buffer(namelist))
        ret = c_uint32(sizeof(namelist))
        return ret


if __name__ == '__main__':
    KEXInitPacket()
    BinaryPacket(None)
