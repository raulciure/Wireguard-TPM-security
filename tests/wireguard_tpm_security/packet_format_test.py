# NOTE: Test module no longer useful for project,
#       as Formatter class is no longer in use

from src.wireguard_tpm_security.packet_format import Formatter

msg = "Hello there, how are you?"
msg_enc = msg.encode()

formatter = Formatter()

packed_msg = formatter.pack(msg_enc)

unpacked_header = formatter.unpack_header(packed_msg)
unpacked_msg = formatter.unpack(packed_msg)

print("msg = ", msg)
print("msg_enc = ", msg_enc)
print("len(msg_enc) = ", len(msg_enc))
print("packed_msg = ", packed_msg)
print("unpacked_header = ", unpacked_header)
print("unpacked_msg = ", unpacked_msg)