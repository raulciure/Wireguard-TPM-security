import struct

# NOTE: Unused class as logic was transfered to netcomm module
class Formatter:
    __header_format : str
    __header_length : int

    def __init__(self, header_format : str = "!H") -> None:
        self.__header_format = header_format
        self.__header_length = struct.calcsize(self.__header_format)

    def pack(self, payload : bytes):
        payload_size = len(payload)
        packet_size = self.__header_length + payload_size
        packed_data = bytearray(packet_size)

        # Pack the header
        struct.pack_into(self.__header_format, packed_data, 0, packet_size)             # Unpack the header

        payload_format = f"!{payload_size}s"

        struct.pack_into(payload_format, packed_data, self.__header_length, payload)    # Unpack the payload (pub key)

        return bytes(packed_data)

    def unpack_header(self, packet : bytes) -> int:
        return struct.unpack_from(self.__header_format, packet, 0)[0]

    def unpack(self, packet : bytes) -> bytes:
        payload_size = self.unpack_header(packet) - self.__header_length                # Unpack the header

        payload_format = f"!{payload_size}s"

        return struct.unpack_from(payload_format, packet, self.__header_length)[0]      # Unpack the payload (pub key) & return