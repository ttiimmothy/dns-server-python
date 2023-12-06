from enum import Enum


class RecordType(Enum):
  A = 1
  NS = 2
  MD = 3
  MF = 4
  CNAME = 5
  SOA = 6
  PTR = 12
  HINFO = 13
  MINFO = 14
  MX = 15
  TXT = 16
