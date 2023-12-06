import copy
import logging
import socket
from dataclasses import dataclass, field
from app.dns.common import debug, ResponseCode, _Address
from app.dns.exceptions import NotImplementedError
from app.dns.header import Header
from app.dns.record import ResourceRecord, Query, Record, BaseRecord

SectionResponse = dict[str, list[Record]]
logger = logging.getLogger(__name__)


@dataclass
class Message:
  header: Header | None = None
  data: bytes = field(default=b'')
  queries: list[Record] = field(default_factory=list)
  answers: list[Record] = field(default_factory=list)
  authorities: list[Record] = field(default_factory=list)
  additional: list[Record] = field(default_factory=list)

  sections = {
      'queries': 'qdcount',
      'answers': 'ancount',
      'authorities': 'nscount',
      'additional': 'arcount',
  }

  def __copy__(self) -> 'Message':
    cls = self.__class__
    result = cls.__new__(cls)
    result.header = copy.copy(self.header)

    for key in Message.sections:
      new_section = []

      section = getattr(self, key)
      if len(section) > 0:
        for q in section:
          qq = copy.copy(q)
          new_section.append(qq)
      setattr(result, key, new_section)

    return result

  def __bytes__(self) -> bytes:
    if not isinstance(self.header, Header):
      logger.error('Missing Header object')
      raise AttributeError(
          'Missing Header',
          name='header',
          obj=self
      )

    if not isinstance(self.queries, list):
      logger.error('Missing Query object')
      raise AttributeError(
          'Missing Query',
          name='header',
          obj=self
      )

    for key, count in Message.sections.items():
      section = getattr(self, key)
      section_size = len(section)
      if section_size < 1:
        logger.info(f'Section {key} has no value')
        continue

      logger.info(
          f'Assigning size of {key} ({section_size}) to Header.{count}'
      )
      setattr(self.header, count, section_size)

    res = bytes(self.header)

    for key in Message.sections:
      section: list[Record] = getattr(self, key)
      logger.info(f'Serializing section: {key}')
      for q in section:
        try:
          res += bytes(q)
        except Exception as e:
          logger.exception(e)
          raise e
    return res

  def serialize(self) -> bytes:
    return bytes(self)

  def validate(self) -> ResponseCode:
    header_res = self.header.validate()

    if header_res != ResponseCode.NO_ERROR:
      return header_res

    for key in Message.sections:
      section: list[Record] = getattr(self, key)
      if len(section) > 0:
        for q in section:
          q_res = q.validate()
          if q_res != ResponseCode.NO_ERROR:
            return q_res
    return ResponseCode.NO_ERROR

  @classmethod
  def from_bytes(cls, data: bytes) -> "Message":
    debug(data=data)
    header = Header.from_bytes(data[:12])
    try:
      container = cls._build_sections(data, header, 12)
    except AttributeError as e:
      logger.exception(e)
      raise e
    return cls(header=header, data=data, **container)

  def create_response(self, resolver: _Address | None = None) -> 'Message':
    if self.header.flags.qr == 1:
      logger.error('Can\'t create a response on a response')
      return self
    message = copy.copy(self)
    res = self.validate()
    if res != ResponseCode.NO_ERROR:
      message.header.flags.qr = 1
      message.header.flags.rcode = res.value
      return message

    for query in message.queries:
      if resolver is None:
        logger.info(f'Creating response for {query.name}')
        record = ResourceRecord.lookup(query=query)
        message.answers.append(record)
      else:
        logger.info(f'Looking up {query.name}')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(self.data, resolver)
        _buf, _ = sock.recvfrom(512)
        sock.close()

        if len(self.data) < len(_buf):
          resolved = Message.from_bytes(data=_buf)
          if len(resolved.answers) > 0:
            for record in resolved.answers:
              message.answers.append(record)
        else:
          record = ResourceRecord.lookup(query=query)
          message.answers.append(record)

    message.header.flags.qr = 1
    message.header.ancount = len(message.answers)
    return message

  @staticmethod
  def _build_sections(data: bytes, header: Header, position: int = 12) -> SectionResponse:
    container: SectionResponse = {}
    for key, count in Message.sections.items():
      if key not in container:
        container[key] = []
      ranger = getattr(header, count)
      logger.info(f'Header.{key} reports {ranger} record(s)')

      if key == 'queries' and ranger < 1:
        raise AttributeError(
            f'Attribute ({count}) requires a positive value',  name=count, object=header)

      if ranger > 0:
        logger.info(f'Building {ranger} record(s) for Header. {key}')
        for _ in range(ranger):
          try:
            if key == 'queries':
              record, position = Query.from_bytes(data, position)
            else:
              record, position = BaseRecord.factory(data, position)
            container[key].append(record)
          except NotImplementedError as e:
            setattr(header, count, ranger - 1)
            logger.warning(e)
            continue
    return container
