import enum
import inspect
import logging
from typing import NewType

DomainName = NewType('DomainName', str)
CharacterString = NewType('CharacterString', str)
_Address = tuple[str, int] | str


def debug(message: str = '', *args: tuple, **kwarg: dict) -> None:
  info = caller_info()
  logger = logging.getLogger('.'.join([info[0], info[1]]))
  offset = kwarg['offset'] if 'offset' in kwarg else 0

  last_message = ''

  if len(args) > 0:
    x = 0
    for value in args:
      name = f'arg{x}'
      res = format_debug_message(value=value, name=name, offset=offset)
      message += res[0]
      last_message += res[1]
      x += 1

  if len(kwarg) > 0:
    for name, value in kwarg.items():
      if name == 'offset':
        continue
      res = format_debug_message(value=value, name=name, offset=offset)
      message += res[0]
      last_message += res[1]
  logger.debug(message + last_message + '\n')


def format_debug_message(
    value, name: str = '', offset: int = 0
) -> tuple[str, str]:
  format_str = '\n[{type}] {name}: {additional}{value}'
  message = ''
  last_message = ''
  tname = type(value)

  if isinstance(value, bytes):
    data_length = len(value) - offset
    p = stringify_bytes(value, offset)
    o = ''
    if offset > 0:
      o = f'{offset}+'
    last_message += format_str.format(type=tname.__name__, name=name,
                                      additional=f'({o}{data_length} bytes)',  value=p)
  else:
    message += ', ' + format_str.format(type=tname.__name__, name=name,
                                        additional='', value=value)
  return message, last_message


def caller_info(skip=2):
  stack = inspect.stack()
  start = 0 + skip
  if len(stack) < start + 1:
    return ''
  parent_frame = stack[start][0]
  module_info = inspect.getmodule(parent_frame)
  if module_info:
    mod = module_info.__name__.split('.')
    package = mod.pop(0)
    module = '.'.join(mod)

  klass = None
  if 'self' in parent_frame.f_locals:
    klass = parent_frame.f_locals['self'].__class__.__name__

  caller = None
  if parent_frame.f_code.co_name != '<module>':
    caller = parent_frame.f_code.co_name
  line = parent_frame.f_lineno
  del parent_frame

  return package, module, klass, caller, line


def stringify_bytes(value: bytes, offset: int = 0) -> str:
  p = ''
  data_length = len(value)
  for z in range(offset, data_length):
    if (z % 16) == 0 or z == offset:
      p += '\n'
    p += '\\x{:0>2x}'.format(value[z])
  return p


def get_random_ip() -> int:
  import random
  range_values = range(0, 255)
  str = '{}.{}.{}.{}'
  str = str.format(
      random.choice(range_values),
      random.choice(range_values),
      random.choice(range_values),
      random.choice(range_values),
  )
  return str


def get_random_ttl() -> int:
  import random
  ttl_values = [60, 300, 1800, 3600, 7200, 14400, 43200, 86400]
  return random.choice(ttl_values)


def setUpRootLogger(level: int = 0) -> logging.Logger:
  root = logging.getLogger()

  if not root.hasHandlers():
    import sys

    if level not in [logging.CRITICAL, logging.ERROR, logging.WARNING,
                     logging.INFO, logging.DEBUG,]:
      level = logging.DEBUG

    root.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)
  return root


def exist_in_enum(value, enum_class: enum.Enum):
  values = set(item.value for item in enum_class)
  if value in values:
    return True
  return False


class EnumExtension(enum.Enum):
  @classmethod
  def value_exists(cls, value) -> bool:
    values = set(item.value for item in cls)
    if value in values:
      return True
    return False

  @classmethod
  def name_exists(cls, name) -> bool:
    names = set(item.name for item in cls)
    if name in names:
      return True
    return False

  @classmethod
  def safe_get_value_by_value(cls, key, default=None):
    if cls.value_exists(key):
      return cls(key).value
    return key if default is None else default

  @classmethod
  def safe_get_name_by_value(cls, key, default=None):
    if cls.value_exists(key):
      return cls(key).name
    return key if default is None else default

  @classmethod
  def safe_get_value_by_name(cls, key, default=None):
    if cls.name_exists(key):
      return cls[key].name
    return key if default is None else default

  @classmethod
  def safe_get_name_by_name(cls, key, default=None):
    if cls.name_exists(key):
      return cls[key].name
    return key if default is None else default


class RClass(EnumExtension):
  IN = 1
  CS = 2
  CH = 3
  HS = 4


class QClass(EnumExtension):
  ANY = 255


class RType(EnumExtension):
  A = 1
  NS = 2
  MD = 3
  MF = 4
  CNAME = 5
  SOA = 6
  MB = 7
  MG = 8
  MR = 9
  NULL = 10
  WKS = 11
  PTR = 12
  HINFO = 13
  MINFO = 14
  MX = 15
  TXT = 16
  RP = 17
  AFSDB = 18
  SIG = 24
  KEY = 25
  AAAA = 28
  LOC = 29
  SRV = 33
  NAPTR = 35
  KX = 36
  CERT = 37
  DNAME = 39
  APL = 42
  DS = 43
  SSHFP = 44
  IPSECKEY = 45
  RRSIG = 46
  NSEC = 47
  DNSKEY = 48
  DHCID = 49
  NSEC3 = 50
  NSEC3PARAM = 51
  TLSA = 52
  SMIMEA = 53
  HIP = 55
  CDS = 59
  CDNSKEY = 60
  OPENPGPKEY = 61
  CSYNC = 62
  ZONEMD = 63
  SVCB = 64
  HTTPS = 65
  EUI48 = 108
  EUI64 = 109
  TKEY = 249
  TSIG = 250
  URI = 256
  CAA = 257
  TA = 32768
  DLV = 32769


class QType(EnumExtension):
  AXFR = 252
  MAILB = 253
  MAILA = 254
  ANY = 255


class OpCode(EnumExtension):
  QUERY = 0


class ResponseCode(EnumExtension):
  NO_ERROR = 0
  FORMAT_ERROR = 1
  SERVER_FAILURE = 2
  NAME_ERROR = 3
  NOT_IMPLEMENTED = 4
  REFUSED = 5
