#!/usr/bin/env python3

# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=line-too-long
# pylint: disable=C0103

import time
import logging
import socket
import sys
import getopt
import struct


def print_help():
    print(
        f"""Usage:
        {sys.argv[0]} [arguments] hostname
        -h  Print this help message
        -v  Enable verbose logging
        """
    )
    sys.exit(0)


# ECHO_TEST_PACKET = b"\x08\x00\xf7\xfc\x00\x02\x00\x01"
# ECHO_REPLY_TEST_PACKET = b"\x00\x00\xbc\xfe\x00\x02\x00\x01"

# https://www.rfc-editor.org/rfc/rfc792


class ICMPConstants:
    # header size constants (bytes)
    TYPE_SIZE = 1
    CODE_SIZE = 1
    CHECKSUM_SIZE = 2
    IDENTIFIER_SIZE = 2
    SEQUENCE_NUM_SIZE = 2
    HEADER_SIZE = 8

    ICMP_TYPE_DEFS: dict = {
        0: "ECHO_REPLY",
        8: "ECHO",
    }

    ICMP_ECHO_CODE = 0


class ICMPEchoMessage:
    def __init__(self):
        self.binary_stream: bytes = None
        self.type = None
        self.code = ICMPConstants.ICMP_ECHO_CODE
        self.checksum = None
        self.identifier = None
        self.sequence_number = None
        self.raw_list = None

    def deserialize(self, packet: bytes):
        logging.info("Initializing ICMP Echo Deserializer")
        self.binary_stream = packet
        self.raw_list = struct.unpack(
            "!BBHHH", self.binary_stream[0 : ICMPConstants.HEADER_SIZE]
        )

        self.type = self.raw_list[0]
        self.code = self.raw_list[1]
        self.checksum = self.raw_list[2]
        self.identifier = self.raw_list[3]
        self.sequence_number = self.raw_list[4]

        # print(self.raw_list)
        logging.info(
            "Type: %s, Checksum: %s, Identifier: %s, Sequence Number: %s",
            self.type,
            self.checksum,
            self.identifier,
            self.sequence_number,
        )

    def serialize(self):
        logging.info("Initializing ICMP Echo Serializer")
        logging.info("Recalculating the checksum")
        self.checksum = 0  # checksum is 0 for calculation!

        # recalculate checksum
        temp_sum = 0
        temp_sum += (self.type << 8) + self.code
        temp_sum += self.checksum
        temp_sum += self.identifier
        temp_sum += self.sequence_number

        temp_sum &= 0xFFFFFFFF
        temp_sum = (temp_sum >> 16) + (temp_sum & 0xFFFF)
        temp_sum += temp_sum >> 16
        self.checksum = ~temp_sum + 0x10000 & 0xFFFF

        logging.info(
            "Type: %s, Checksum: %s, Identifier: %s, Sequence Number: %s",
            self.type,
            self.checksum,
            self.identifier,
            self.sequence_number,
        )
        # pack the binary
        self.binary_stream = struct.pack(
            "!BBHHH",
            self.type,
            self.code,
            self.checksum,
            self.identifier,
            self.sequence_number,
        )


# Function to send ping
def send_ping(hostname, message):
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # set connection timeout
    icmp_socket.settimeout(TIMEOUT)
    icmp_socket.sendto(message, (hostname, 1))
    start_timestamp, end_timestamp, address, ip_ttl, ip_size, icmp_reply = receive_ping(
        icmp_socket
    )
    icmp_socket.close()
    return start_timestamp, end_timestamp, address, ip_ttl, ip_size, icmp_reply


# Function to receive a ping and return two timestamps
def receive_ping(icmp_socket):
    start_timestamp = time.time()
    end_timestamp = None
    # receive a ping
    try:
        received_binary, address = icmp_socket.recvfrom(1024)
        ip_header = received_binary[:20]
        ip_size = len(received_binary)
        ip_header_raw_list = struct.unpack("!BBHHHBBHII", ip_header)
        ip_ttl = ip_header_raw_list[5]
        icmp_header = received_binary[20:28]
        icmp_reply = ICMPEchoMessage()
        icmp_reply.deserialize(icmp_header)

        end_timestamp = time.time()
    # handle timeout errors
    except TimeoutError:
        print("Request timed out")
        return start_timestamp, -1, None, 0, 0, None
    return start_timestamp, end_timestamp, address, ip_ttl, ip_size, icmp_reply


# Function to calculate and return the delay
def check_delay(start, end):
    if end == -1:
        return -1
    else:
        # return in milliseconds with 2 decimals
        return round((end - start) * 1000, 2)


def display_status(address, delay, ttl, seq, size):
    print(f"{size} bytes from {address[0]}: icmp_seq={seq} ttl={ttl} time={delay}ms ")


OPTIONS = "hv"
verbose = False

try:
    ARGS, VALUES = getopt.getopt(sys.argv[1:], OPTIONS)
    # if nothing is given
    if len(sys.argv) == 0:
        print_help()
    # process parsed args
    HOSTNAME = sys.argv[-1]
    for arg, val in ARGS:
        match arg:
            case "-h":
                print_help()
            case "-v":
                verbose = True
            case _:
                print_help()
except getopt.error as e:
    print(str(e))


# verbose

if verbose:
    logging.basicConfig(
        format="%(levelname)s:%(funcName)s:%(lineno)d:%(message)s", level=logging.DEBUG
    )
else:
    logging.basicConfig(
        format="%(levelname)s:%(funcName)s:%(lineno)d:%(message)s",
        level=logging.WARNING,
    )


# program begin

TIMEOUT = 1

echo_packet = ICMPEchoMessage()
echo_packet.type = 8  # echo request
echo_packet.identifier = 2000
echo_packet.sequence_number = 0
echo_packet.serialize()

print(
    f"PING {HOSTNAME} ({socket.gethostbyname(HOSTNAME)}) in Python: {len(echo_packet.binary_stream)} data bytes"
)

while True:
    try:
        (
            start_timestamp,
            end_timestamp,
            address,
            ip_ttl,
            ip_size,
            icmp_reply,
        ) = send_ping(HOSTNAME, echo_packet.binary_stream)
        if end_timestamp != -1:
            display_status(
                address,
                check_delay(start_timestamp, end_timestamp),
                ip_ttl,
                icmp_reply.sequence_number,
                ip_size,
            )

        # increment sequence number and serialize again
        echo_packet.sequence_number += 1
        echo_packet.serialize()
        # add delay to avoid packet spams
        time.sleep(TIMEOUT)
    except KeyboardInterrupt:
        print("\b\b\b\bUser interrupted program, exiting.")
        sys.exit()
