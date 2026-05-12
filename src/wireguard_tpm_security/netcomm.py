import struct
import socket
    

class NetComm:
    __conn_socket : socket.socket
    __header_format : str
    __header_length : int
    __max_msg_size : int

    def __init__(self, conn_socket : socket.socket, header_format : str = "!H", max_msg_size : int | None = None) -> None:
        self.__conn_socket = conn_socket
        self.__header_format = header_format
        self.__header_length = struct.calcsize(self.__header_format)

        if max_msg_size is None:
            self.__max_msg_size = 1024 * 1024   # 1 MB max message size (default)
        else:
            self.__max_msg_size = max_msg_size

    def __recv_exact(self, num : int):
        segments = []
        received = 0
        
        while received < num:
            recv_segment = self.__conn_socket.recv(num - received)

            if not recv_segment:
                raise ConnectionError("*** Socket closed before enough data was received! ***")
            
            segments.append(recv_segment)
            received += len(recv_segment)

        return b''.join(segments)

    def send(self, data : bytes):
        if len(data) > self.__max_msg_size:
            raise ValueError(f"*** Message size exceeded!\nMaximum: {self.__max_msg_size} bytes | Actual: {len(data)} bytes ***")
        
        header = struct.pack(self.__header_format, len(data))
        self.__conn_socket.sendall(header + data)

    def receive(self):
        header = self.__recv_exact(self.__header_length)
        payload_size = struct.unpack(self.__header_format, header)[0]

        if payload_size > self.__max_msg_size:
            raise ValueError(f"*** Message size exceeded!\nMaximum: {self.__max_msg_size} bytes | Actual: {payload_size} bytes ***")
        
        return self.__recv_exact(payload_size)
