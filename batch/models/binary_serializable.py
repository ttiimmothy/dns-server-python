from abc import ABC, abstractmethod


class BinarySerializable(ABC):
  @classmethod
  def from_bytes(bytes):
    raise NotImplementedError("Method unimplemented")

  @abstractmethod
  def to_bytes(self):
    raise NotImplementedError("Method unimplemented")
