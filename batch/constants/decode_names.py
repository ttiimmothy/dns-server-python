NAME_LENGTH_POINTER_MASK = 0xC0


def _is_pointer(length_byte):
  return length_byte & NAME_LENGTH_POINTER_MASK == NAME_LENGTH_POINTER_MASK


def DecodeNames(name_bytes: bytes):
  result = []
  name_table = (
      dict()
  )
  index = 0
  length_byte = name_bytes[index]
  is_last_byte_pointer = False
  while length_byte > 0:
    if _is_pointer(length_byte):
      length_byte_without_pointer_flag = length_byte & 0x3F
      if length_byte_without_pointer_flag not in name_table:
        raise ValueError(
            f"Specified {length_byte_without_pointer_flag} was not found. Either this is incorrectly referencing a future name label or is pointing to the wrong place in general"
        )
      result.append(name_table[length_byte_without_pointer_flag])
      index += 2
      is_last_byte_pointer = True
    else:
      name = name_bytes[index + 1: index + length_byte + 1].decode()
      name_table[index] = name
      result.append(name)
      index += length_byte + 1
      is_last_byte_pointer = False
    length_byte = name_bytes[index]
  if not is_last_byte_pointer:
    index += 1

  return result, index
