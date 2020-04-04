import socket as soc
import argparse
import sys
import os
import Crypto.Cipher as ciphers
from Crypto.Util import Padding
from exceptions import *
import ctypes


class SSHPacket:
    """
    uint32    packet_length
    byte      padding_length
    byte[n1]  payload; n1 = packet_length - padding_length - 1
    byte[n2]  random padding; n2 = padding_length
    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
    """

    def __init__(self, payload):
        pass


class TCPConnection:
    # Set identifier string, don't include null char per RFC spec
    identifier_string = 'SSH-2.0-mmmunozSSH0.1\r\n'.split('\x00')[0]

    def __init__(self, destination, port, username):
        self.client_socket = soc.socket(soc.AF_INET, soc.SOCK_STREAM)
        self.username = username
        self.serverTuple = (destination, port)
        self.connect()
        try:
            self.handshake()
        except SSHException as err:
            print(f'Fatal error occurred, exiting...\n{err}', file=sys.stderr)
            sys.exit(1)
        except BaseException as err:
            print(f'Unexpected error occurred, exiting...\n{err}', file=sys.stderr)
            sys.exit(2)

    def connect(self) -> None:
        self.client_socket.connect(self.serverTuple)

    def handshake(self):
        pass

    @staticmethod
    def main():
        arg_parser = argparse.ArgumentParser()
        required = arg_parser.add_argument_group('Required arguments')
        required.add_argument('-d', '--destination', help='Destination IP address or hostname', required=True)
        arg_parser.add_argument('-u', '--username', help='Username used to login to the remote SSH client')
        arg_parser.add_argument('-p', '--port', type=int,
                                help='The port to connect to on the remote server. Defaults to 22.')
        args = arg_parser.parse_args()
        port = args.port or 22
        connection = TCPConnection(destination=args.destination, port=port, username=args.username)


if __name__ == '__main__':
    TCPConnection.main()
