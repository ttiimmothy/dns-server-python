import struct
from typing import List


def EncodeNames(name: List[bytes]):
  result = b""
  for label in name:
    length = struct.pack("!B", len(label))
    result += (
        length + label.encode()
    )
  result += b"\x00"
  return result
