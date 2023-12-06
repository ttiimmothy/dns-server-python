import logging
import struct
from app.dns.exceptions import FormatError
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from app.dns.common import CharacterString, DomainName

logger = logging.getLogger(__name__)


class Encoding:
  @staticmethod
  def encode_domain_name(parts: list[str]) -> bytes:
    res = b''
    for part in parts:
      ascii_part = part.encode('ascii')
      part_length = len(ascii_part)
      if part_length >= 63:
        raise FormatError(
            'Part \'{}\' of \'{}\' exceeds limit of 63 chars'
            .format(part, '.'.join(parts))
        )
      res += len(ascii_part).to_bytes(1, 'big') + ascii_part

    res = res + b'\x00'
    return res

  @staticmethod
  def encode_character_string(value: 'CharacterString') -> bytes:
    res = b''
    ascii_value = value.encode('ascii')
    res += len(ascii_value).to_bytes(1, 'big') + ascii_value

    res = res + b'\x00'
    return res

  @staticmethod
  def encode_ip(parts: list[int]) -> bytes:
    res = b''
    for part in parts:
      res += int(part).to_bytes(1, 'big')
    return res

  @staticmethod
  def encode(value: str) -> bytes:
    value = value.replace('@', '.')
    value = value.replace('-', '.')
    value = value.replace('+', '.')
    parts = value.split('.')
    try:
      if isinstance(int(parts[0]), int):
        return Encoding.encode_ip(parts)
    except ValueError:
      return Encoding.encode_domain_name(parts)

  @staticmethod
  def decode_domain_name(data: bytes, offset: int = 0) -> tuple['DomainName', int]:
    i = offset
    parts = []
    while True:
      length = int.from_bytes(data[i:i+1], 'big')

      if data[i] == 0x00:
        i += 1
        break
      elif (length & 0xc0 == 0xc0):
        pointer = struct.unpack("!H", data[i:i+2])[0]
        pointer &= 0x3fff
        i += 2
        name = Encoding.decode_domain_name(data, pointer)[0]
        parts.append(name)
        break
      else:
        i += 1
        if (i + length) > len(data):
          break

        payload = data[i:i + length]
        try:
          name = payload.decode('utf-8')
          parts.append(name)
        except UnicodeDecodeError:
          pass
        i += length

    name = '.'.join(parts)

    return (name, i)

  @staticmethod
  def decode_character_string(data: bytes, offset: int = 0) -> tuple['CharacterString', int]:
    length = int.from_bytes(data[offset:1], 'big')
    res = data[offset+1:length].decode('utf-8')

    return (res, length + 1)

  @staticmethod
  def decode_ip(data: bytes, offset: int = 0) -> tuple[str, int]:
    res = '{}.{}.{}.{}'.format(int.from_bytes(data[offset+0:offset+1], 'big'), int.from_bytes(
        data[offset+1:offset+2], 'big'), int.from_bytes(data[offset+2:offset+3], 'big'), int.from_bytes(data[offset+3:offset+4], 'big'))
    return (res, 4)

  @staticmethod
  def decode(data: bytes, offset: int = 0) -> tuple[str, int]:
    if data[-1] == b'\x00':
      return Encoding.decode_ip(data, offset)
    else:
      return Encoding.decode_domain_name(data, offset)
