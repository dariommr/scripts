#!/var/ossec/framework/python/bin/python3

import argparse
import sys
from socket import socket, AF_UNIX, SOCK_DGRAM
import json

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

# Send event to Wazuh manager
def send_event(head, msg):
    #logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:{}:{}'.format(head, msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    # Parse arguments
    epilogue = "This is a tool designed to inject logs into the Wazuh Socket, choose the appropriate header and run it, then the program will wait for the logs via stdin. Press 'q' to exit."
    parser = argparse.ArgumentParser(prog='Wazuh Socket Injector', description='Wazuh - Inject events into Wazuh socket.', epilog=epilogue)
    parser.add_argument('--header', metavar='sock_header', type=str, required = True, help='The header for the socket message, this will be taken by the engine as the "location" for the alert.')
    args = parser.parse_args()

    for line in sys.stdin:
        if 'q' == line.rstrip():
            break
        send_event(args.header, line)
