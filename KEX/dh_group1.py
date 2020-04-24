import os
import struct
from Crypto.Util.number import *
from Crypto.Hash import SHA1
from packets import *
from Authentication.ssh_rsa import SSHRsa
from exceptions import SSHException


class DHGroup1:
    # Group 1 prime
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
    G = 2

    def __init__(self):
        self.x = int(0).to_bytes(128, 'big')  # type: bytes
        self.e = int(0).to_bytes(128, 'big')  # type: bytes
        self.f = int(0).to_bytes(128, 'big')  # type: bytes
        self.rsa = SSHRsa(r'.\Authentication\host_keys')

    def get_dhkex_init_packet(self) -> bytes:
        self.__calculate_x()
        self.e = pow(self.G, int.from_bytes(self.x, 'big'), self.P)
        e_bytes = self.e.to_bytes(size(self.e), 'big')
        # Remove leading zero bytes
        byte_ind = 0
        for byte_ind, byte in enumerate(e_bytes):
            if byte != 0:
                break
        e_bytes = e_bytes[byte_ind:]
        payload = struct.pack(f'!BL{len(e_bytes)}B', SSH_MSG_KEXDH_INIT, len(e_bytes), *e_bytes)
        return bytes(BinaryPacket(payload))

    def __calculate_x(self) -> None:
        q = struct.pack('!d', (self.P - 1) / 2)
        while True:
            self.x = os.urandom(128)
            if int(1).to_bytes(128, 'big') < self.x < q:
                break

    def parse_dhkex_reply_packet(self, binary_packet: BinaryPacket, server_version, c_kex_init, s_kex_init):
        data, packet = next_n_bytes(bytes(binary_packet.payload), 5)
        packet_type, str_len = struct.unpack('!BL', data)
        host_key_type_len, packet = next_n_bytes(packet, 4)
        host_key_type, packet = next_n_bytes(packet, struct.unpack('!L', host_key_type_len)[0])
        if host_key_type.decode('utf-8') != 'ssh-rsa':
            raise SSHException('Unimplemented host key authentication')
        rsa_e_len, packet = next_n_bytes(packet, 4)
        rsa_e, packet = next_n_bytes(packet, struct.unpack('!L', rsa_e_len)[0])
        rsa_n_len, packet = next_n_bytes(packet, 4)
        rsa_n, packet = next_n_bytes(packet, struct.unpack('!L', rsa_n_len)[0])
        message_len, packet = next_n_bytes(packet, 4)
        self.f, packet = next_n_bytes(packet, struct.unpack('!L', message_len)[0])
        kex_sig_len, packet = next_n_bytes(packet, 4)
        kex_sig, packet = next_n_bytes(packet, struct.unpack('!L', kex_sig_len)[0])

        key = pow(int.from_bytes(self.f, 'big'), int.from_bytes(self.x, 'big'), self.P)

        h = SHA1.new()
        h.update(client_version.encode())
        h.update(server_version.encode())
        h.update(c_kex_init)
        h.update(s_kex_init)
        h.update(self.e)
        h.update(self.f)
        h.update(key.to_bytes(size(key), 'big'))
        h.digest()

        rsa_n_len = struct.unpack('!L', rsa_n_len)[0]
        rsa_e_len = struct.unpack('!L', rsa_e_len)[0]

        if not self.rsa.validate_hostkey(h, kex_sig,
                                         (int.from_bytes(struct.unpack(f'!{rsa_n_len}B', rsa_n), 'big'),
                                          int.from_bytes(struct.unpack(f'!{rsa_e_len}B', rsa_e), 'big'))):
            raise SSHException('Invalid host key')
        print(f'DH_KEY = {key}')
        return key
