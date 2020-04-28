import os
import struct
from Crypto.Util.number import *
from Crypto.Hash import SHA1, HMAC
from Crypto.PublicKey import RSA
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
        self.key = None  # type: Union[int, None]
        self.rsa = SSHRsa(r'.\Authentication\hostkeys')

    def get_dhkex_init_packet(self) -> bytes:
        self.generate_x()
        self.e = pow(self.G, int.from_bytes(self.x, 'big'), self.P)
        # self.e = self.e.to_bytes(ceil_div(size(self.e), 8), 'big')
        self.e = self.e.to_bytes(129, 'big')
        # Remove leading zero bytes
        byte_ind = 0
        for byte_ind, byte in enumerate(self.e):
            if byte != 0:
                break
        self.e = self.e[byte_ind:]
        print(f'e = {hex(int.from_bytes(self.e, "big"))}')
        payload = struct.pack(f'!BL', SSH_MSG_KEXDH_INIT, len(self.e)) + self.e
        return bytes(BinaryPacket(payload))

    def generate_x(self) -> None:
        q = (self.P - 1) / 2
        while 1 > int.from_bytes(self.x, 'big') or int.from_bytes(self.x, 'big') > q:
            self.x = os.urandom(128)

    def get_key(self):
        return self.key

    def parse_dhkex_reply_packet(self, binary_packet: BinaryPacket, server_version: str, c_kex_init: bytes,
                                 s_kex_init: bytes, hostname: str):
        data, packet = next_n_bytes(bytes(binary_packet.payload), 5)
        packet_type, str_len = struct.unpack('!BL', data)
        host_key_type_len, packet = next_n_bytes(packet, 4)
        host_key_type, packet = next_n_bytes(packet, struct.unpack('!L', host_key_type_len)[0])
        if host_key_type.decode('utf-8') != 'ssh-rsa':
            raise SSHException('Unimplemented host key authentication')

        rsa_e_len, packet = next_n_bytes(packet, 4)
        rsa_e_len = struct.unpack('!L', rsa_e_len)[0]
        rsa_e, packet = next_n_bytes(packet, rsa_e_len)

        rsa_n_len, packet = next_n_bytes(packet, 4)
        rsa_n_len = struct.unpack('!L', rsa_n_len)[0]
        rsa_n, packet = next_n_bytes(packet, rsa_n_len)

        message_len, packet = next_n_bytes(packet, 4)
        self.f, packet = next_n_bytes(packet, struct.unpack('!L', message_len)[0])
        kex_sig_len, packet = next_n_bytes(packet, 4)
        kex_sig_type_len, packet = next_n_bytes(packet, 4)
        kex_sig_type_len = struct.unpack('!L', kex_sig_type_len)[0]
        kex_sig_type, packet = next_n_bytes(packet, kex_sig_type_len)
        kex_sig_len, packet = next_n_bytes(packet, 4)
        kex_sig_len = struct.unpack('!L', kex_sig_len)[0]
        kex_sig, packet = next_n_bytes(packet, kex_sig_len)

        # hash_host_key = as_ssh_string(kex_sig_type) + bytes(0)

        K = pow(int.from_bytes(self.f, 'big'), int.from_bytes(self.x, 'big'), self.P)
        self.key = K.to_bytes(ceil_div(size(K), 8), 'big')

        hash_host_key = as_ssh_string(kex_sig_type) + as_mpint(rsa_e) + as_mpint(rsa_n)

        rsa_e = int.from_bytes(struct.unpack(f'>{rsa_e_len}B', rsa_e), 'big')
        rsa_n = int.from_bytes(struct.unpack(f'>{rsa_n_len}B', rsa_n), 'big')
        hostkey = RSA.construct((rsa_n, rsa_e))

        c_v = client_version.rstrip('\r\n')
        s_v = server_version.rstrip('\r\n')

        h = SHA1.new()
        h.update(as_ssh_string(c_v))
        h.update(as_ssh_string(s_v))
        h.update(as_ssh_string(c_kex_init))
        h.update(as_ssh_string(s_kex_init))
        h.update(as_ssh_string(hash_host_key))
        print(hash_host_key, file=sys.stderr)
        h.update(as_mpint(self.e))
        h.update(as_mpint(self.f))
        h.update(as_mpint(self.key))
        h = h.digest()
        self.h = h

        iv_c2s = SHA1.new(as_mpint(K))
        iv_c2s.update(h)
        iv_c2s.update("A".encode('ASCII'))
        iv_c2s.update(h)
        iv_c2s = iv_c2s.digest()[:16]

        iv_s2c = SHA1.new(as_mpint(K))
        iv_s2c.update(h)
        iv_s2c.update("B".encode('ASCII'))
        iv_s2c.update(h)
        iv_s2c = iv_s2c.digest()[:16]

        enc_c2s = SHA1.new(as_mpint(K))
        enc_c2s.update(h)
        enc_c2s.update("C".encode('ASCII'))
        enc_c2s.update(h)
        enc_c2s = enc_c2s.digest()
        while len(enc_c2s) < 32:
            old_k = enc_c2s
            enc_c2s = SHA1.new(as_mpint(K))
            enc_c2s.update(h)
            enc_c2s.update(old_k)
            enc_c2s = old_k + enc_c2s.digest()
        enc_c2s = enc_c2s[:32]

        enc_s2c = SHA1.new(as_mpint(K))
        enc_s2c.update(h)
        enc_s2c.update("D".encode('ASCII'))
        enc_s2c.update(h)
        enc_s2c = enc_s2c.digest()
        while len(enc_s2c) < 32:
            old_k = enc_s2c
            enc_s2c = SHA1.new(as_mpint(K))
            enc_s2c.update(h)
            enc_s2c.update(old_k)
            enc_s2c = old_k + enc_s2c.digest()
        enc_s2c = enc_s2c[:32]

        int_c2s = SHA1.new(as_mpint(K))
        int_c2s.update(h)
        int_c2s.update("E".encode('ASCII'))
        int_c2s.update(h)
        int_c2s = int_c2s.digest()

        int_s2c = SHA1.new(as_mpint(K))
        int_s2c.update(h)
        int_s2c.update("F".encode('ASCII'))
        int_s2c.update(h)
        int_s2c = int_s2c.digest()

        if not self.rsa.validate_hostkey(h, kex_sig, (rsa_n, rsa_e), hostname):
            # raise SSHException('Invalid host key')
            print('DEBUG: Invalid hostkey, ignoring', file=sys.stderr)

        print(f'DH_KEY = {K}')
        return iv_c2s, iv_s2c, enc_c2s, enc_s2c, int_c2s, int_s2c
