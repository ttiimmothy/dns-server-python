import struct
from dataclasses import dataclass
from app.models.binary_serializable import BinarySerializable

DNS_HEADER_STRUCT_FORMAT = "!HccHHHH"
NETWORK_BYTE_ORDER = "big"
BYTE_LENGTH = 12


@dataclass
class Header(BinarySerializable):
  id: int = 1234
  qr: int = 1
  opcode: int = 0
  aa: int = 0
  tc: int = 0
  rd: int = 0
  ra: int = 0
  z: int = 0
  rcode: int = 0
  qdcount: int = 0
  ancount: int = 0
  nscount: int = 0
  arcount: int = 0

  @classmethod
  def from_bytes(cls, bytes):
    id = struct.unpack("!H", bytes[:2])[0]
    byte_3 = bytes[2]
    qr = (byte_3 >> 7) & 0b1
    opcode = (byte_3 >> 3) & 0b1111
    aa = (byte_3 >> 2) & 0b1
    tc = (byte_3 >> 1) & 0b1
    rd = byte_3 & 0b1
    byte_4 = bytes[3]
    ra = (byte_4 >> 7) & 0b1
    z = (byte_4 >> 4) & 0b111
    rcode = byte_4 & 0b1111
    qdcount = struct.unpack("!H", bytes[4:6])[0]
    ancount = struct.unpack("!H", bytes[6:8])[0]
    nscount = struct.unpack("!H", bytes[8:10])[0]
    arcount = struct.unpack("!H", bytes[10:12])[0]
    return (
        cls(
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        ),
        BYTE_LENGTH,
    )

  def to_bytes(self) -> bytes:
    h_id = self.id
    c_qr_flags = (
        self.qr << 7 | self.opcode << 3 | self.aa << 2 | self.tc << 1 | self.rd
    )
    c_qr_flags = c_qr_flags.to_bytes(
        byteorder=NETWORK_BYTE_ORDER, signed=False)
    c_ra_flags = self.ra << 7 | self.z << 4 | self.rcode
    c_ra_flags = c_ra_flags.to_bytes(
        byteorder=NETWORK_BYTE_ORDER, signed=False)
    h_qdcount = self.qdcount
    h_ancount = self.ancount
    h_nscount = self.nscount
    h_arcount = self.arcount
    return struct.pack(
        DNS_HEADER_STRUCT_FORMAT,
        h_id,
        c_qr_flags,
        c_ra_flags,
        h_qdcount,
        h_ancount,
        h_nscount,
        h_arcount,
    )

  @staticmethod
  def to_response_header(header):
    response_header = Header.to_response_header(dns_message.header)
    return Message(response_header, dns_message.questions, new_answers)
