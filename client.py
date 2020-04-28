import socket as soc
import argparse
import sys
import os
import Crypto.Cipher as ciphers
from Crypto.Util import Padding
from exceptions import *
from packets import *
from utils import *
from KEX.dh_group1 import DHGroup1
from Authentication import ssh_rsa


class SSHConnection:

    def __init__(self, destination, port, username):
        self.running = False
        self.client_socket = soc.socket(soc.AF_INET, soc.SOCK_STREAM)
        self.username = username
        self.serverTuple = (destination, port)
        self.server_version = None
        self.packet_gen = PacketGenerator(self.client_socket)
        self.key = None  # type: Union[int, None]

        self.iv_c2s = None
        self.iv_s2c = None
        self.enc_c2s = None
        self.enc_s2c = None
        self.int_c2s = None
        self.int_s2c = None

        self.connect()
        try:
            self.run()
        except SSHException as err:
            print(f'Fatal error occurred, exiting...\n{err}', file=sys.stderr)
            self.client_socket.close()
            sys.exit(1)
        except BaseException as err:
            print(f'Unexpected error occurred, exiting...\n{err}', file=sys.stderr)
            self.client_socket.close()
            sys.exit(2)
        input('Press enter to close connection')
        self.client_socket.close()

    def connect(self) -> None:
        """
        Connects to the destination over the specified port
        :return: None
        """
        self.client_socket.connect(self.serverTuple)

    def run(self):
        """
        Perform the initial SSH handshake
        :raises SSHException: Indicates that a non-recoverable exception occurred during the handshake
        :return: None
        """
        server_kex_init = None
        dh_group = DHGroup1()
        dh_group.generate_x()
        self.running = True
        self.client_socket.send(client_version.encode())
        ret = self.client_socket.recv(2048)
        self.server_version = ret.decode()
        print(f'Server version: {self.server_version}')
        print(f'Sending KEX_INIT packet')
        client_kex_packet = BinaryPacket(KEXInitPacket().get_packet())
        self.client_socket.send(bytes(client_kex_packet))
        while self.running:
            try:
                print(f'Receiving packet')
                packet_type, packet = self.packet_gen.receive_binary_packet()
                print(f'Packet type: {packet_type} Data: {str(packet)}')
            except ValueError as v:
                self.running = False
                raise SSHException(f'Unexpected packet received, ending session.\nException info: {str(v)}')
            if packet_type == SSH_MSG_KEX_INIT:
                server_kex_init = packet
                self.packet_gen.parse_kex_init_packet(packet.payload)
                kex_packet = dh_group.get_dhkex_init_packet()
                self.client_socket.send(bytes(kex_packet))
            elif packet_type == SSH_MSG_KEXDH_REPLY:
                self.iv_c2s, self.iv_s2c, self.enc_c2s, self.enc_s2c, self.int_c2s, \
                self.int_s2c = dh_group.parse_dhkex_reply_packet(packet,
                                                                 self.server_version,
                                                                 client_kex_packet.payload,
                                                                 server_kex_init.payload,
                                                                 self.serverTuple[0])
            elif packet_type == SSH_MSG_NEW_KEYS:
                self.packet_gen.send_newkeys(self.iv_c2s, self.iv_s2c, self.enc_c2s, self.enc_s2c,
                                             self.int_c2s, self.int_s2c)
                self.packet_gen.send_auth_request(self.username)
            elif packet_type == SSH_MSG_DISCONNECT:
                self.running = False
                print(f'Disconnect received, ending connection')
            else:
                self.running = False
                print(f'Unknown SSH packet type {packet_type}, ending session')
        self.client_socket.close()

    @staticmethod
    def main():
        """
        Initiates the SSH connection with the specified program arguments
        :return:
        """
        arg_parser = argparse.ArgumentParser()
        required = arg_parser.add_argument_group('Required arguments')
        required.add_argument('-d', '--destination', help='Destination IP address or hostname', required=True)
        arg_parser.add_argument('-u', '--username', help='Username used to login to the remote SSH client')
        arg_parser.add_argument('-p', '--port', type=int,
                                help='The port to connect to on the remote server. Defaults to 22.')
        args = arg_parser.parse_args()
        port = args.port or 22
        connection = SSHConnection(destination=args.destination, port=port, username=args.username)


# Run the class if called directly, otherwise allow other file to import class
if __name__ == '__main__':
    SSHConnection.main()
