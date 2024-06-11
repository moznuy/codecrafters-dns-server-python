from __future__ import annotations

import dataclasses
import logging
import socket
import struct
from typing import Any


@dataclasses.dataclass(kw_only=True, frozen=True)
class DnsHeader:
    identifier: int  # 16 bits
    is_response: bool  # 1 bit
    operation_code: int  # 4 bits
    is_authoritative_answer: bool  # 1 bit
    is_truncated: bool  # 1 bit
    is_recursion_desired: bool  # 1 bit
    is_recursion_available: bool  # 1 bit
    reserved: int  # 3 bits
    response_code: int  # 4 bits
    question_count: int  # 16 bits
    answer_record_count: int  # 16 bits
    authority_record_count: int  # 16 bits
    additional_record_count: int  # 16 bits

    @classmethod
    def parse_header(cls, payload: bytes) -> tuple[DnsHeader | None, bytes]:
        if len(payload) < 12:
            return None, payload

        header, rest = payload[:12], payload[12:]
        results = struct.unpack(">HHHHHH", header)
        (
            identifier,
            flags,
            question_count,
            answer_record_count,
            authority_record_count,
            additional_record_count,
        ) = results
        is_response = (flags & 0x8000) != 0
        operation_code = (flags & 0x7800) >> 11
        is_authoritative_answer = (flags & 0x0400) != 0
        is_truncated = (flags & 0x0200) != 0
        is_recursion_desired = (flags & 0x0100) != 0
        is_recursion_available = (flags & 0x0080) != 0
        reserved = (flags & 0x0070) >> 4
        response_code = (flags & 0x000F) >> 0

        # assert reserved == 0 # dig sends 0b010

        return (
            DnsHeader(
                identifier=identifier,
                is_response=is_response,
                operation_code=operation_code,
                is_authoritative_answer=is_authoritative_answer,
                is_truncated=is_truncated,
                is_recursion_desired=is_recursion_desired,
                is_recursion_available=is_recursion_available,
                reserved=0,
                response_code=response_code,
                question_count=question_count,
                answer_record_count=answer_record_count,
                authority_record_count=authority_record_count,
                additional_record_count=additional_record_count,
            ),
            rest,
        )

    def serialize(self) -> bytes:
        assert 0 <= self.operation_code < 2**4
        assert self.reserved == 0
        assert 0 <= self.response_code < 2**4

        flags = (
            (int(self.is_response) << 15)
            | (self.operation_code << 11)
            | (int(self.is_authoritative_answer) << 10)
            | (int(self.is_truncated) << 9)
            | (int(self.is_recursion_desired) << 8)
            | (int(self.is_recursion_available) << 7)
            | (self.reserved << 4)
            | (self.response_code << 0)
        )
        assert 0 <= flags < 2**16

        return struct.pack(
            ">HHHHHH",
            self.identifier,
            flags,
            self.question_count,
            self.answer_record_count,
            self.authority_record_count,
            self.additional_record_count,
        )


# Question Types
# A               1 a host address
# NS              2 an authoritative name server
# MD              3 a mail destination (Obsolete - use MX)
# MF              4 a mail forwarder (Obsolete - use MX)
# CNAME           5 the canonical name for an alias
# SOA             6 marks the start of a zone of authority
# MB              7 a mailbox domain name (EXPERIMENTAL)
# MG              8 a mail group member (EXPERIMENTAL)
# MR              9 a mail rename domain name (EXPERIMENTAL)
# NULL            10 a null RR (EXPERIMENTAL)
# WKS             11 a well known service description
# PTR             12 a domain name pointer
# HINFO           13 host information
# MINFO           14 mailbox or mail list information
# MX              15 mail exchange
# TXT             16 text strings

# Question Classes
# IN              1 the Internet
# CS              2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
# CH              3 the CHAOS class
# HS              4 Hesiod [Dyer 87]


@dataclasses.dataclass(kw_only=True, frozen=True)
class DnsQuestion:
    names: list[str]
    type: int
    klass: int

    # @property
    # def name(self):
    #     return ".".join(self.names)

    @classmethod
    def parse_question(cls, payload: bytes) -> tuple[DnsQuestion | None, bytes]:
        names: list[str] = []

        while True:
            if len(payload) < 1:
                return None, payload
            length, payload = payload[0], payload[1:]
            if length == 0:
                break
            if len(payload) < length:
                return None, payload
            raw_name, payload = payload[:length], payload[length:]
            names.append(raw_name.decode())

        if len(payload) < 4:
            return None, payload
        fields, payload = payload[:4], payload[4:]
        typ, klass = struct.unpack(">HH", fields)
        return DnsQuestion(names=names, type=typ, klass=klass), payload

    def serialize(self) -> bytes:
        result = serialize_names(self.names)
        result += struct.pack(">HH", self.type, self.klass)
        return result


def serialize_names(names: list[str]) -> bytes:
    result = b""
    for name in names:
        length = len(name)
        assert length < 64
        result += struct.pack(">B", length)
        result += name.encode()
    result += b"\x00"
    return result


@dataclasses.dataclass(kw_only=True, frozen=True)
class DnsAnswer:
    names: list[str]
    type: int
    klass: int
    ttl: int
    data: Any

    def serialize(self) -> bytes:
        # TODO: same code
        result = serialize_names(self.names)
        result += struct.pack(">HHL", self.type, self.klass, self.ttl)

        # A Record
        assert self.klass == 1
        assert isinstance(self.data, str)
        result += struct.pack(">H", 4)
        result += socket.inet_aton(self.data)

        return result


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("0.0.0.0", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            request_header, rest = DnsHeader.parse_header(buf)
            if request_header is None:
                raise RuntimeError("Header Error")
            questions: list[DnsQuestion] = []
            for _ in range(request_header.question_count):
                question, rest = DnsQuestion.parse_question(rest)
                if question is None:
                    raise RuntimeError("Question Error")
                questions.append(question)

            print(request_header)
            print(questions)

            response_header = DnsHeader(
                identifier=request_header.identifier,
                is_response=True,
                operation_code=request_header.operation_code,
                is_authoritative_answer=False,
                is_truncated=False,
                is_recursion_desired=request_header.is_recursion_desired,
                is_recursion_available=False,
                reserved=0,
                response_code=0 if request_header.operation_code == 0 else 4,
                question_count=request_header.question_count,
                answer_record_count=request_header.question_count,
                authority_record_count=0,
                additional_record_count=0,
            )

            response = DnsHeader.serialize(response_header)
            for question in questions:
                response += question.serialize()
            for question in questions:
                response += DnsAnswer(
                    names=question.names,
                    type=question.type,
                    klass=question.klass,
                    ttl=60,
                    data="8.8.8.8",
                ).serialize()

            udp_socket.sendto(response, source)
        except Exception:
            logging.exception("Error receiving data:")
            continue


if __name__ == "__main__":
    main()
