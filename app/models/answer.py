from dataclasses import dataclass
import struct
from typing import List
from app.constants.encode_names import EncodeNames
from app.constants.decode_names import DecodeNames
from app.models.binary_serializable import BinarySerializable
from app.libs.record_class import RecordClass
from app.libs.record_type import RecordType


@dataclass
class Answer(BinarySerializable):
  name: List[str]
  type: RecordType = RecordType.A
  classes: RecordClass = RecordClass.IN
  ttl: int = 60
  length: int = 4
  rdata: str = b"8.8.8.8"

  @classmethod
  def from_bytes(cls, bytes):
    name, index = DecodeNames(bytes)
    rdata_start = index + 10
    fields = struct.unpack("!HHIH", bytes[index:rdata_start])
    type = RecordType(fields[0])
    classes = RecordClass(fields[1])
    ttl = fields[2]
    length = fields[3]
    rdata = bytes[rdata_start: rdata_start + length]
    return cls(name, type, classes, ttl, length, rdata), rdata_start + length

  def to_bytes(self):
    result = b""
    result += EncodeNames(self.name)
    result += struct.pack(
        "!HHIH", self.type.value, self.classes.value, self.ttl, self.length
    )
    result += self.rdata
    return result
