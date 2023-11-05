#!/usr/bin/env python3

# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=line-too-long
# pylint: disable=C0103

import copy
import logging
import socket
import sys
import csv
import getopt
import struct
import ipaddress
import random


def print_help():
    print(
        f"""Usage:
        {sys.argv[0]} [arguments]
        -h  Print this help message
        -s  Operate in server mode
        -c  Operate in client mode
        -t  Test mode
        -a  DNS server address for client mode
        -d  Domain name to query
        -q  DNS record type to query for in client mode
        -i  Operate as an interactive DNS client
        -v  Enable verbose logging
        """
    )
    sys.exit(0)


class DnsConstants:

    # size constants (bytes)
    HEADER_SIZE: int = 12
    QDCOUNT_SIZE: int = 2
    ANCOUNT_SIZE: int = 2
    NSCOUNT_SIZE: int = 2
    ARCOUNT_SIZE: int = 2
    QTYPE_SIZE: int = 2
    QCLASS_SIZE: int = 2
    RR_TYPE_SIZE: int = 2
    RR_CLASS_SIZE: int = 2
    RR_TTL_SIZE: int = 4
    RR_RDLENGTH_SIZE: int = 2

    # lookup tables
    RCODE_DEFS: dict = {
        0: "NOERROR",
        1: "FORMAT_ERROR",
        2: "SERVFAIL",
        3: "NAME_ERROR",
        4: "NOT_IMPLEMENTD",
        5: "REFUSED",
        6: "RESERVED",
        7: "RESERVED",
        8: "RESERVED",
        9: "RESERVED",
        10: "RESERVED",
        11: "RESERVED",
        12: "RESERVED",
        13: "RESERVED",
        14: "RESERVED",
        15: "RESERVED",
    }

    # https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
    RR_TYPE_DEFS: dict = {
        1: "A",
        2: "NS",
        3: "MD",
        4: "MF",
        5: "CNAME",
        6: "SOA",
        7: "MB",
        8: "MG",
        9: "MR",
        10: "NULL",
        11: "WKS",
        12: "PTR",
        13: "HINFO",
        14: "MINFO",
        15: "MX",
        16: "TXT",
    }

    # https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
    QTYPE_DEFS: dict = {
        1: "A",
        2: "NS",
        3: "MD",
        4: "MF",
        5: "CNAME",
        6: "SOA",
        7: "MB",
        8: "MG",
        9: "MR",
        10: "NULL",
        11: "WKS",
        12: "PTR",
        13: "HINFO",
        14: "MINFO",
        15: "MX",
        16: "TXT",
        252: "AXFR",
        253: "MAILB",
        254: "MAILA",
        255: "*",
    }

    # https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
    RR_CLASS_DEFS: dict = {
        1: "IN",
        2: "CS",
        3: "CH",
        4: "HS",
    }

    # https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.5
    QCLASS_DEFS: dict = {
        1: "IN",
        2: "CS",
        3: "CH",
        4: "HS",
        255: "*",
    }


class DnsMessage:
    def __init__(self):
        self.binary_stream: bytes = None
        self.header = DnsMessage.Header(self)
        self.questions: list = []
        self.answers: list = []
        self.nameserver_records: list = []

    def deserialize(self, wireformat: bytes):
        current_offset = 0
        self.binary_stream: bytes = wireformat
        logging.info("Initializing DNS Serializer")
        # First 12 bytes is the header
        self.header = DnsMessage.Header(self)
        self.header.deserialize()
        logging.info(
            "Message type: %s.", "Answer" if self.header.qr == 1 else "Question"
        )

        # Question processing
        self.questions: list = []
        current_offset += DnsConstants.HEADER_SIZE
        logging.info(
            "Starting to process %i question(s), at offset %s",
            self.header.qdcount,
            hex(current_offset),
        )
        # for each question
        for i in range(self.header.qdcount):
            logging.info("Processing question %i at offset %s", i, hex(current_offset))
            current_question = DnsMessage.Question(self)
            current_question.deserialize(current_offset)
            current_offset += current_question.size

            # add current question to the list
            self.questions.append(current_question)
            logging.info(
                "Question processing done, finishing at offset %s", hex(current_offset)
            )
        # Answer processing
        logging.info(
            "Starting to process %i answer(s), at offset %s",
            self.header.ancount,
            hex(current_offset),
        )
        self.answers: list = []
        for i in range(self.header.ancount):
            logging.info("Processing answer %i at offset %s", i, hex(current_offset))
            # make a new RR obj, deserialize data and increment current size
            current_resource_record = DnsMessage.ResourceRecord(self)
            current_resource_record.deserialize(current_offset)
            current_offset += current_resource_record.rr_size
            # add this RR to the list of answers
            self.answers.append(current_resource_record)
        # Nameserver Record processing
        logging.info(
            "Starting to process %i nameserver records(s), at offset %s",
            self.header.nscount,
            hex(current_offset),
        )
        self.nameserver_records: list = []
        for i in range(self.header.nscount):
            logging.info(
                "Processing nameserver record %i at offset %s", i, hex(current_offset)
            )
            # make a new RR obj, deserialize data and increment current size
            current_resource_record = DnsMessage.ResourceRecord(self)
            current_resource_record.deserialize(current_offset)
            current_offset += current_resource_record.rr_size
            # add this RR to the list of answers
            self.nameserver_records.append(current_resource_record)

    def serialize(self):
        # clear old values
        self.binary_stream: bytes = b""
        # serialize everything
        self.header.serialize()
        for question in self.questions:
            question.serialize()
        for answer in self.answers:
            answer.serialize()

    def __str__(self):
        string_output = ""
        string_output += str(self.header) + "\n"
        for question in self.questions:
            string_output += str(question) + "\n"
        for answer in self.answers:
            string_output += str(answer) + "\n"
        return string_output

    def parse_labels(self, offset: int):
        logging.info("Parsing a label at offset %s", hex(offset))
        initial_offset = offset
        labels: list = []
        ptr_used: bool = False
        while self.binary_stream[offset] > 0 and not ptr_used:
            if (self.binary_stream[offset] & 0b11000000) >> 6 == 0b11:
                ptr_used = True
                offset += 1  # processed size/pinter flag (1 byte)
                ptr_dest = self.binary_stream[offset]
                logging.info(
                    "Found a pointer, parsing the labels at pointer destination %s.",
                    hex(ptr_dest),
                )
                ptr_labels_size, qname = self.parse_labels(ptr_dest)
                # offset += ptr_labels_size  # processed pointer
                offset += 1
                labels.extend(qname)
            else:
                logging.info("Parsing regular label at offset: %s", hex(offset))
                label_size = self.binary_stream[offset]
                offset += 1  # processed size (1 byte)
                current_label_content = str(
                    self.binary_stream[offset : offset + label_size], "ascii"
                )
                logging.info(
                    "Label size: %s, Label: %s", hex(label_size), current_label_content
                )
                labels.append(current_label_content)
                offset += label_size  # processed label
            logging.info("Label parsing loop done, at offset: %s", hex(offset))
            if offset >= len(self.binary_stream):
                logging.info(
                    "Label parsing terminated at the end of the DNS message, at offset: %s",
                    hex(offset),
                )
                break
        if not ptr_used:
            offset += 1  # final terminating zero-length label's size byte
        size: int = offset - initial_offset
        logging.info(
            "Label parsing finished, size: %s, labels: %s, is pointer: %i",
            hex(size),
            labels,
            ptr_used,
        )
        return size, labels

    def encode_labels(self, labels):
        logging.info("Starting to encode labels.")
        encoded_labels = b""
        for l in labels:
            encoded_labels += struct.pack("!B", len(l))
            encoded_labels += bytes(l, "ascii")
        encoded_labels += b"\x00"  # trailing zero-size label
        logging.info("Finished encoding the labels: %s", encoded_labels)
        return encoded_labels

    class Header:
        def __init__(self, dnsmessage):
            # The header contains the following fields:
            #                                 1  1  1  1  1  1
            #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |                      ID                       |
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |                    QDCOUNT                    |
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |                    ANCOUNT                    |
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |                    NSCOUNT                    |
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            # |                    ARCOUNT                    |
            # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            self.raw_list: list = []
            self.dnsmessage = dnsmessage
            self.id: int = None
            self.qr: int = None
            self.opcode: int = None
            self.aa: int = 0
            self.tc: int = 0
            self.rd: int = 0
            self.ra: int = 0
            self.rcode: int = 0

            self.qdcount: int = 0
            self.ancount: int = 0
            self.nscount: int = 0
            self.arcount: int = 0

        def deserialize(self):
            self.raw_list = struct.unpack(
                "!HBBHHHH", self.dnsmessage.binary_stream[0 : DnsConstants.HEADER_SIZE]
            )
            self.id = self.raw_list[0]
            self.qr = (self.raw_list[1] & 0b10000000) >> 7
            self.opcode = (self.raw_list[1] & 0b01111000) >> 3
            self.aa = (self.raw_list[1] & 0b00000100) >> 2
            self.tc = (self.raw_list[1] & 0b00000010) >> 1
            self.rd = self.raw_list[1] & 0b00000001
            self.ra = (self.raw_list[2] & 0b10000000) >> 7
            self.rcode = self.raw_list[2] & 0b00001111
            self.qdcount = self.raw_list[3]
            self.ancount = self.raw_list[4]
            self.nscount = self.raw_list[5]
            self.arcount = self.raw_list[6]

        def serialize(self):
            self.raw_list = [0, 0, 0, 0, 0, 0, 0]
            self.raw_list[0] = self.id
            self.raw_list[1] |= (self.qr << 7) & 0b10000000
            self.raw_list[1] |= (self.opcode << 3) & 0b01111000
            self.raw_list[1] |= (self.aa << 2) & 0b00000100
            self.raw_list[1] |= (self.tc << 1) & 0b00000010
            self.raw_list[1] |= (self.rd) & 0b00000001
            self.raw_list[2] = self.rcode & 0b00001111
            self.raw_list[3] = self.qdcount
            self.raw_list[4] = self.ancount
            self.raw_list[5] = self.nscount
            self.raw_list[6] = self.arcount
            header_binary: bytes = b""
            header_binary += struct.pack(
                "!HBBHHHH",
                self.raw_list[0],
                self.raw_list[1],
                self.raw_list[2],
                self.raw_list[3],
                self.raw_list[4],
                self.raw_list[5],
                self.raw_list[6],
            )
            logging.info("Serialized header: %s", header_binary)
            self.dnsmessage.binary_stream += header_binary

        def __str__(self):
            return (
                "DNS Message Header: \n"
                + f"ID: {self.id} \n"
                + f"Type: {'Answer' if self.qr == 1 else 'Question'} \n"
                + f"Authoriatitive: {'Yes' if self.aa == 1 else 'No'} \n"
                + f"RCODE: {DnsConstants.RCODE_DEFS[self.rcode]} \n"
                + f"Question count: {self.qdcount} \n"
                + f"Answer count: {self.ancount} \n"
                + f"Nameserver record count: {self.nscount} \n"
            )

    class Question:
        def __init__(self, dnsmessage):
            # The section contains QDCOUNT (usually 1) entries, each of the following format:
            #                                     1  1  1  1  1  1
            #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            #     |                                               |
            #     /                     QNAME                     /
            #     /                                               /
            #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            #     |                     QTYPE                     |
            #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            #     |                     QCLASS                    |
            #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            self.dnsmessage = dnsmessage
            self.offset: int = None
            self.qname: list = b""
            self.qtype: int = 0
            self.qclass: int = 0
            self.size: int = None

        def deserialize(self, offset: int):
            self.offset = offset
            # parse QNAME (labels)
            qname_size, self.qname = self.dnsmessage.parse_labels(offset)
            offset += qname_size

            # QTYPE (2 bytes) and QCLASS (2 bytes)
            self.qtype = int.from_bytes(
                (
                    self.dnsmessage.binary_stream[
                        offset : offset + DnsConstants.QTYPE_SIZE
                    ]
                ),
                "big",
            )
            offset += DnsConstants.QTYPE_SIZE
            self.qclass = int.from_bytes(
                self.dnsmessage.binary_stream[
                    offset : offset + DnsConstants.QCLASS_SIZE
                ],
                "big",
            )
            offset += DnsConstants.QCLASS_SIZE
            self.size = offset - self.offset

        def serialize(self):
            # encode qname
            encoded_qname = self.dnsmessage.encode_labels(self.qname)
            self.dnsmessage.binary_stream += encoded_qname
            logging.info("Encoded QNAME: %s", encoded_qname)
            # encode qtype and qclass
            encoded_qtype_qclass = struct.pack("!HH", self.qtype, self.qclass)
            self.dnsmessage.binary_stream += encoded_qtype_qclass
            logging.info("Question serialzation complete")

    class ResourceRecord:
        def __init__(self, dnsmessage):
            # placeholders
            self.dnsmessage = dnsmessage
            self.rr_offset: int = 0
            self.rr_size: int = None
            self.name: list = []
            self.type: int = 0
            self.data_class: int = 0
            self.ttl: int = 0
            self.rdlength: int = 0
            self.rdata: bytes = ""
            self.rdata_offset: int = 0
            self.rdata_decoded: str = ""

        def deserialize(self, offset: int):
            self.rr_offset = offset
            # process the NAME section
            name_size, self.name = self.dnsmessage.parse_labels(offset)
            offset += name_size
            # process fixed data sections (type, class, ttl and rdlength)
            raw_param_tuple = struct.unpack(
                "!HHIH",
                self.dnsmessage.binary_stream[
                    offset : offset
                    + DnsConstants.RR_TYPE_SIZE
                    + DnsConstants.RR_CLASS_SIZE
                    + DnsConstants.RR_TTL_SIZE
                    + DnsConstants.RR_RDLENGTH_SIZE
                ],
            )
            # process the type section
            self.type = raw_param_tuple[0]
            offset += DnsConstants.RR_TYPE_SIZE
            # process the class section
            self.data_class = raw_param_tuple[1]
            offset += DnsConstants.RR_CLASS_SIZE
            # process the TTL section
            self.ttl = raw_param_tuple[2]
            offset += DnsConstants.RR_TTL_SIZE
            # process the rdlength section
            self.rdlength = raw_param_tuple[3]
            offset += DnsConstants.RR_RDLENGTH_SIZE
            # process rdata
            self.rdata_offset = offset
            self.rdata = self.dnsmessage.binary_stream[offset : offset + self.rdlength]
            offset += self.rdlength
            self.rr_size = offset - self.rr_offset
            # all done, call decoding method to decode the rdata to a printable string
            self.decode_rdata()

        def serialize(self):
            logging.info("Serializing RR")
            # name
            encoded_name = self.dnsmessage.encode_labels(self.name)
            self.dnsmessage.binary_stream += encoded_name
            logging.info("Encoded NAME: %s", encoded_name)
            # type, class, ttl, rdlength
            rr_params = struct.pack(
                "!HHIH", self.type, self.data_class, self.ttl, self.rdlength
            )
            self.dnsmessage.binary_stream += rr_params
            # rdata
            logging.info("Serializing RDATA")
            rdata_type: str = DnsConstants.RR_TYPE_DEFS[self.type]
            match rdata_type:
                case "A":
                    logging.info("RDATA type: A")
                    ipv4 = list(map(int, str(self.rdata_decoded).split(".")))
                    logging.info("IP address to encode: %s", ipv4)
                    self.rdata = struct.pack(
                        "!BBBB",
                        ipv4[0],
                        ipv4[1],
                        ipv4[2],
                        ipv4[3],
                    )
                case "CNAME":
                    logging.info("RDATA type: CNAME")
                    self.rdata = self.dnsmessage.encode_labels(
                        self.rdata_decoded.split(".")
                    )
                case _:
                    logging.info(
                        "Serializing RDATA type %s is not supported.", rdata_type
                    )
            logging.info("Encoded RDATA: %s", self.rdata)
            print((self.dnsmessage.binary_stream))
            self.dnsmessage.binary_stream += self.rdata
            print((self.dnsmessage.binary_stream))

        def decode_rdata(self):
            logging.info("Decoding RDATA")
            rdata_type: str = DnsConstants.RR_TYPE_DEFS[self.type]
            match rdata_type:
                case "A":
                    logging.info("RDATA type: A")
                    logging.info("RDATA: %s", len(self.rdata))

                    ipv4 = struct.unpack("!BBBB", self.rdata)
                    self.rdata_decoded = f"{ipv4[0]}.{ipv4[1]}.{ipv4[2]}.{ipv4[3]}"
                    logging.info("Decoded RDATA: %s", self.rdata_decoded)
                case "CNAME":
                    logging.info("RDATA type: CNAME")
                    size, labels = self.dnsmessage.parse_labels(self.rdata_offset)
                    self.rdata_decoded = ".".join(labels)
                    logging.info("Decoded RDATA: %s", self.rdata_decoded)
                case "SOA":
                    logging.info("RDATA type: SOA")
                    # SOA RDATA format
                    #
                    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    # /                     MNAME                     /
                    # /                                               /
                    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    # /                     RNAME                     /
                    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    # |                    SERIAL                     |
                    # |                                               |
                    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    # |                    REFRESH                    |
                    # |                                               |
                    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    # |                     RETRY                     |
                    # |                                               |
                    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    # |                    EXPIRE                     |
                    # |                                               |
                    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    # |                    MINIMUM                    |
                    # |                                               |
                    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    current_offset = self.rdata_offset
                    logging.info("MNAME parsing starting at %s", hex(current_offset))
                    mname_size, mname = self.dnsmessage.parse_labels(current_offset)
                    logging.info(
                        "MNAME parsing finished, size: %s, labels: %s",
                        hex(mname_size),
                        mname,
                    )
                    self.rdata_decoded += f"\n  MNAME: {'.'.join(mname)}"
                    current_offset += mname_size
                    logging.info("RNAME parsing starting at %s", hex(current_offset))
                    rname_size, rname = self.dnsmessage.parse_labels(current_offset)
                    logging.info(
                        "RNAME parsing finished, size: %s, labels: %s",
                        hex(rname_size),
                        rname,
                    )
                    self.rdata_decoded += f"\n  RNAME: {'.'.join(rname)}"
                    current_offset += rname_size
                    # parse the other five 32-bit params
                    params = struct.unpack(
                        "!IIIII",
                        self.dnsmessage.binary_stream[
                            # 5 uint of size 4 (bytes)
                            current_offset : current_offset
                            + 5 * 4
                        ],
                    )
                    logging.info(
                        "SOA SERIAL: %i, REFRESH: %i, RETRY: %i, EXPIRE: %i, MINIMUM: %i",
                        params[0],
                        params[1],
                        params[2],
                        params[3],
                        params[4],
                    )
                case _:
                    logging.info("RDATA type %s is not supported.", rdata_type)

        def __str__(self):
            return (
                "DNS Resource Record: \n"
                + f"Name: {'.'.join(self.name)} \n"
                + f"Type: {DnsConstants.RR_TYPE_DEFS[self.type]} \n"
                + f"Class: {DnsConstants.RR_CLASS_DEFS[self.data_class]} \n"
                + f"TTL: {self.ttl} second(s) \n"
                + f"Data: {self.rdata_decoded} \n"
            )


###########################################################
# END DNS MODULE
###########################################################


# services.addons.mozilla.com
TEST_QUERY: bytes = b"\x45\x1f\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x08\x73\x65\x72\x76\x69\x63\x65\x73\x06\x61\x64\x64\x6f\x6e\x73\x07\x6d\x6f\x7a\x69\x6c\x6c\x61\x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29\x05\xc0\x00\x00\x00\x00\x00\x00"
TEST_ANSWER: bytes = b"\x45\x1f\x81\x80\x00\x01\x00\x04\x00\x00\x00\x01\x08\x73\x65\x72\x76\x69\x63\x65\x73\x06\x61\x64\x64\x6f\x6e\x73\x07\x6d\x6f\x7a\x69\x6c\x6c\x61\x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x36\xe6\x15\x41\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x36\xe6\x15\x21\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x36\xe6\x15\x55\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x36\xe6\x15\x18\x00\x00\x29\xff\xd6\x00\x00\x00\x00\x00\x00"
TEST_ANSWER_CNAME: bytes = b"\xc3\x91\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x03\x77\x77\x77\x06\x67\x69\x74\x68\x75\x62\x03\x63\x6f\x6d\x00\x00\x05\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x0d\xeb\x00\x02\xc0\x10\x00\x00\x29\xff\xd6\x00\x00\x00\x00\x00\x00"


OPTIONS = "hscta:d:q:iv"
LONG_OPTIONS = [
    "--help",
    "--server",
    "--client",
    "--test-mode",
    "--address=",
    "--domain-name",
    "--query-type=",
    "--interactive",
    "--verbose",
]

is_server_mode: bool = False
is_client_mode: bool = False
is_test_mode: bool = False
verbose: bool = False
is_interactive_mode: bool = False
query_type: str = "A"  # default to A
domain_name: str = ""  # default empty string
server_address: str = "9.9.9.9"  # default to quad9
DNS_RECORD_FILE: str = "dns.csv"

try:
    ARGS, VALUES = getopt.getopt(sys.argv[1:], OPTIONS, LONG_OPTIONS)
    # if nothing is given
    if len(ARGS) == 0:
        print_help()
    # process parsed args
    for arg, val in ARGS:
        match arg:
            case "-h":
                print_help()
            case "-s":
                is_server_mode = True
            case "-c":
                is_client_mode = True
            case "-t":
                is_test_mode = True
            case "-a":
                if len(val) != 0:
                    try:
                        # IP Address validation
                        ipaddress.ip_address(val)
                        server_address = val
                    except ValueError:
                        print("Server address given is not a valid IP address.")
                        exit(1)
            case "-d":
                domain_name = val
            case "-q":
                if len(val) != 0:
                    query_type = val
            case "-i":
                is_interactive_mode = True
            case "-v":
                verbose = True
            case _:
                print_help()
except getopt.error as e:
    print(str(e))

# mode conflicts
if [is_server_mode, is_client_mode, is_test_mode, is_interactive_mode].count(True) > 1:
    print("You may not specify more than one mode.")
    sys.exit(1)

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

# test mode
if is_test_mode:
    print("Test mode")
    a = DnsMessage()
    a.deserialize(TEST_QUERY)
    b = DnsMessage()
    b.deserialize(TEST_ANSWER)
    c = DnsMessage()
    c.deserialize(TEST_ANSWER_CNAME)
    print(a.header, b.header, c.header)
    print(b.answers[0], c.answers[0])

    # test serialization
    print(TEST_ANSWER)
    b.serialize()
    print(b.binary_stream)

    # test with dns server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(1.0)
    addr = ("9.9.9.9", 53)
    client_socket.sendto(a.binary_stream, addr)
    data, server = client_socket.recvfrom(10000)
    # process response data
    print(f"{data}")
    d = DnsMessage()
    d.deserialize(data)
    sys.exit(0)

# server mode
if is_server_mode:
    print("Operating in server mode")
    logging.info("Reading CSV file")
    reader = csv.DictReader(open(DNS_RECORD_FILE))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 53))
    while True:
        data, clientaddr = server_socket.recvfrom(1024)
        if not data:
            break
        query = DnsMessage()

        # check data
        try:
            query.deserialize(data)
            print(query)
        except Exception as e:
            logging.warning(e)
            sys.exit(1)

        # valid query
        answer_found = False
        answer = copy.deepcopy(query)

        for row in reader:
            logging.info("Checking key: %s, type: %s", row["key"], row["type"])
            qname = ".".join(query.questions[0].qname)
            qtype = str(query.questions[0].qtype)

            logging.info("Query key: %s", qname)
            logging.info("Query type: %s", qtype)

            if row["key"] == qname and row["type"] == qtype:
                logging.info("Record found")
                answer_found = True
                answer.header.qr = 1  # answer
                answer.header.ancount += 1  # 1 answer

                match int(qtype):
                    case 1:  # A
                        logging.info("A record")
                        answer_rr = DnsMessage.ResourceRecord(answer)
                        answer.answers.append(answer_rr)
                        answer.answers[0].name = query.questions[0].qname
                        answer.answers[0].type = query.questions[0].qtype
                        answer.answers[0].ttl = 60
                        answer.answers[0].data_class = query.questions[0].qclass
                        answer.answers[0].rdlength = 4
                        answer.answers[0].rdata_decoded = row["value"]
                    case 5:  # CNAME
                        logging.info("CNAME record")
                        answer_rr = DnsMessage.ResourceRecord(answer)
                        answer.answers.append(answer_rr)
                        answer.answers[0].name = query.questions[0].qname
                        answer.answers[0].type = query.questions[0].qtype
                        answer.answers[0].ttl = 60
                        answer.answers[0].data_class = query.questions[0].qclass
                        cname_data = row["value"].split(".")
                        for l in cname_data:
                            logging.info("%s", l)
                            answer.answers[0].rdlength += 1
                            answer.answers[0].rdlength += len(l)
                        answer.answers[0].rdata_decoded = row["value"]
                    case _:
                        logging.info("Unsupported query type %s", qtype)
            if not answer_found:
                answer.header.rcode = 3

        answer.serialize()
        server_socket.sendto(answer.binary_stream, clientaddr)


# client mode
if is_client_mode:
    print("Operating in client mode")
    query = DnsMessage()
    query.header.id = random.randint(0, 65536)
    query.header.qr = 0  # question
    query.header.qdcount = 1
    query.header.rd = 1
    query.header.opcode = 0  # standard query
    query.questions.append(DnsMessage.Question(query))
    query.questions[0].qname = list(domain_name.split("."))
    match query_type:
        case "A":
            query.questions[0].qtype = 1
        case "CNAME":
            query.questions[0].qtype = 5
        case _:
            print("Unsupported query type, only A and CNAME are supported.")
            sys.exit(1)
    query.questions[0].qclass = 1
    query.serialize()
    logging.debug(query.binary_stream)
    # send query
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(1.0)
    addr = (server_address, 53)
    client_socket.sendto(query.binary_stream, addr)
    data, server = client_socket.recvfrom(10000)
    # process response data
    logging.debug(data)
    response = DnsMessage()
    response.deserialize(data)
    for rr in response.answers:
        print(rr)

# interactive mode
if is_interactive_mode:
    print("Operating in interactive mode")
    print("Not implemented yet")
