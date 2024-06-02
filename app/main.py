from __future__ import annotations

import dataclasses
import socket
import struct


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

        assert reserved == 0

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


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            request_header, rest = DnsHeader.parse_header(buf)
            if request_header is None:
                raise RuntimeError("Payload to short")
            print(request_header)

            response_header = DnsHeader(
                identifier=request_header.identifier,
                is_response=True,
                operation_code=0,
                is_authoritative_answer=False,
                is_truncated=False,
                is_recursion_desired=False,
                is_recursion_available=False,
                reserved=0,
                response_code=0,
                question_count=0,
                answer_record_count=0,
                authority_record_count=0,
                additional_record_count=0,
            )

            response = DnsHeader.serialize(response_header)
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
