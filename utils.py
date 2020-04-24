import sys

# Set identifier string
client_version = 'SSH-2.0-mwmunozSSH0.1\r\n'


def byte_tuple_to_str(byte_tuple: tuple) -> str:
    return ''.join(c.decode() for c in byte_tuple)


def next_n_bytes(packet, n):
    """
    Returns the next n bytes of the packet as well as the remaining unread packet
    :param packet: bytes of a packet
    :type packet: bytes
    :param n: the number of bytes to read
    :type n: int
    :return: a tuple containing the next n bytes and the remaining unread packet
    :rtype: (bytes, bytes)
    """
    ret = packet[:n]
    remaining_packet = packet[n:]
    return bytes(ret), bytes(remaining_packet)


def prompt_user(prompt: str) -> bool:
    """
    Prompts the user with a yes/no question and returns their answer as a bool
    :param prompt: The message to show the user
    :type prompt: str
    :return: The user's answer to the prompt
    :rtype: bool
    """
    positive_response = {'yes', 'y', 'ye', '', 'ok'}
    negative_response = {'no', 'n'}

    while True:
        answer = input(prompt).lower()
        if answer in positive_response:
            return True
        elif answer in negative_response:
            return False
        else:
            print("Please respond with 'yes' or 'no'\n", file=sys.stderr)
