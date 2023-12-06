import struct
from dataclasses import dataclass
from typing import List
from app.models.binary_serializable import BinarySerializable
from app.libs.record_class import RecordClass
from app.libs.record_type import RecordType
from app.constant.encode_names import EncodeNames
from app.constants.decode_names import DecodeNames


@dataclass
class Question(BinarySerializable):
  name: List[str]
  type: RecordType = RecordType.A
  classes: RecordClass = RecordClass.IN

  @classmethod
  def from_bytes(cls, bytes):
    print(bytes)
    name, index = DecodeNames(bytes)
    print("after", bytes[index:])
    fields = struct.unpack(
        "!HH", bytes[index: index + 4]
    )
    type = RecordType(fields[0])
    classes = RecordClass(fields[1])
    print("after2", bytes[index + 4:])
    return cls(name, type, classes), index + 4

  def to_bytes(self):
    result = EncodeNames(self.name)
    result += struct.pack("!HH", self.type.value, self.classes.value)
    return result
