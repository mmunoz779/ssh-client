import os
from typing import Union

from Crypto.Util import Padding
from utils import *
import socket
import struct


def str_to_bytes(string: str):
    ret = []
    for c in string:
        ret.append(bytes(c, 'utf-8'))
    return ret


def as_namelist(namelist: str):
    # Remove any spaces
    ret = str_to_bytes(','.join([name.strip() for name in namelist.split(',')]))
    return struct.pack('!L%dc' % len(ret), len(ret), *ret)


# Defines the different packet types
SSH_MSG_DISCONNECT = 1
SSH_MSG_KEX_INIT = 20
SSH_MSG_KEXDH_INIT = 30
SSH_MSG_KEXDH_REPLY = 31

SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_USERAUTH_BANNER = 53
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_SUCCESS = 91
SSH_MSG_CHANNEL_OPEN_FAILURE = 92
SSH_MSG_CHANNEL_CLOSE = 97
SSH_MSG_CHANNEL_REQUEST = 98
SSH_MSG_CHANNEL_SUCCESS = 99
SSH_MSG_CHANNEL_FAILURE = 100


# Prototype class for use in type checking
class _GenericPacket:
    pass


class PacketGenerator:

    def __init__(self, sock=None):
        self.kex_alg = None
        self.hk_alg_server = None
        self.enc_alg_c2s = None
        self.enc_alg_s2c = None
        self.mac_alg_c2s = None
        self.mac_alg_s2c = None
        self.compress_alg_c2s = None
        self.compress_alg_s2c = None
        self.lang_c2s = None
        self.lang_s2c = None
        self.socket = sock

    def receive_binary_packet(self, mac_alg=None) -> (bytes, _GenericPacket):
        recv = self.socket.recv(5)
        packet_len, pad_len = struct.unpack('>LB', recv)
        recv = self.socket.recv(packet_len - 1 - pad_len)  # - 1 due to already reading padding_length
        payload = recv
        if mac_alg:
            self.socket.recv(mac_alg.length())
        packet = BinaryPacket(payload=payload, packet_len=packet_len, pad_len=pad_len)
        packet_type = struct.unpack('!B', next_n_bytes(bytes(payload), 1)[0])[0]
        self.socket.recv(pad_len)
        return packet_type, packet

    def parse_kex_init_packet(self, packet):
        data, packet = next_n_bytes(packet, 17)
        packet_type, *cookie = struct.unpack('!17B', data)
        data, packet = next_n_bytes(packet, 4)
        for name_list in KEXInitPacket.name_lists:
            name_list_size = struct.unpack('!L', data)[0]
            data, packet = next_n_bytes(packet, name_list_size)
            res = struct.unpack('!%dc' % name_list_size, data)
            self.__setattr__(name_list, res if len(res) > 0 else bytes('', 'utf-8'))
            if name_list != KEXInitPacket.name_lists[-1]:
                data, packet = next_n_bytes(packet, 4)
        data, packet = next_n_bytes(packet, 5)
        first_kex_packet_follows, reserved = struct.unpack('!?L', data)
        print(f'{packet_type}\n{[c for c in cookie]}\n' +
              '\n'.join([byte_tuple_to_str(self.__getattribute__(name_list)) for name_list in
                         KEXInitPacket.name_lists]) +
              f'\n{first_kex_packet_follows}\n{reserved}')


class _GenericPacket(PacketGenerator):
    """
    Functions useful for all packets, used as superclass only
    """

    def __init__(self, sock=None):
        super().__init__(sock)
        self.packet = None

    def __len__(self):
        return len(self.packet)

    def __bytes__(self):
        return self.packet

    def __str__(self):
        return str(self.packet)

    def get_packet(self):
        return self.packet


class BinaryPacket(_GenericPacket):
    """
    uint32    packet_length
    byte      padding_length
    byte[n1]  payload; n1 = packet_length - padding_length - 1
    byte[n2]  random padding; n2 = padding_length
    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
    """

    def __init__(self, payload: Union[bytes], packet_len=None, pad_len=None, block_size=8, sock=None):
        super().__init__(sock)
        self.padding_length = pad_len if pad_len is not None else 3 + block_size - ((len(payload) + 8) % block_size)
        self.packet_length = packet_len if packet_len is not None else len(payload) + self.padding_length + 1
        self.payload = payload
        self.random_padding = struct.pack(f'!{self.padding_length}B', *int(0).to_bytes(self.padding_length, 'big'))
        self.packet = struct.pack(f'!LB{self.packet_length - self.padding_length - 1}B', self.packet_length,
                                  self.padding_length, *payload) + self.random_padding
        if self.mac_alg_c2s is not None:
            pass  # Compute HMAC of message


class NewKeysPacket(_GenericPacket):

    def __init__(self, sock=None):
        super().__init__(sock)
        self.SSH_MSG_NEWKEYS = 21
        self.packet = struct.pack('!B', self.SSH_MSG_NEWKEYS)


class KEXInitPacket(_GenericPacket):
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

    fstr1 = '!B16B'
    fstr2 = '!?L'

    name_lists = ['kex_algorithms', 'server_host_key_algorithms', 'encryption_algorithms_client_to_server',
                  'encryption_algorithms_server_to_client', 'mac_algorithms_client_to_server',
                  'mac_algorithms_server_to_client', 'compression_algorithms_client_to_server',
                  'compression_algorithms_server_to_client', 'language_client_to_server',
                  'language_server_to_client']

    def __init__(self, sock=None):
        super().__init__(sock)
        self.cookie = os.urandom(16)  # type: bytes
        # self.kex_algorithms = as_namelist('diffie-hellman-group1-sha1, diffie-hellman-group14-sha1')
        self.kex_algorithms = as_namelist('diffie-hellman-group1-sha1')
        # self.server_host_key_algorithms = as_namelist('ssh-rsa, ssh-dss, pgp-sign-rsa, pgp-sign-dss')
        self.server_host_key_algorithms = as_namelist('ssh-rsa')
        self.encryption_algorithms_client_to_server = as_namelist('aes256-cbc, 3des-cbc')
        self.encryption_algorithms_server_to_client = as_namelist('aes256-cbc, 3des-cbc')
        self.mac_algorithms_client_to_server = as_namelist('hmac-sha1')
        self.mac_algorithms_server_to_client = as_namelist('hmac-sha1')
        self.compression_algorithms_client_to_server = as_namelist('none')
        self.compression_algorithms_server_to_client = as_namelist('none')
        self.languages_client_to_server = as_namelist('')
        self.languages_server_to_client = as_namelist('')
        self.first_kex_packet_follows = True  # type: bool
        self.reserved = 0  # type: int
        self.packet = struct.pack(self.fstr1, SSH_MSG_KEX_INIT, *self.cookie) + self.kex_algorithms \
                      + self.server_host_key_algorithms + self.encryption_algorithms_client_to_server \
                      + self.encryption_algorithms_server_to_client + self.mac_algorithms_client_to_server \
                      + self.mac_algorithms_server_to_client + self.compression_algorithms_client_to_server \
                      + self.compression_algorithms_server_to_client + self.languages_client_to_server \
                      + self.languages_server_to_client + struct.pack(self.fstr2, self.first_kex_packet_follows,
                                                                      self.reserved)


if __name__ == '__main__':
    PacketGenerator()
