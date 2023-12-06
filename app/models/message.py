from dataclasses import dataclass
from typing import List
from app.models.answer import Answer
from app.models.header import Header
from app.models.question import Question
from app.models.binary_serializable import BinarySerializable


@dataclass
class Message(BinarySerializable):
  header: Header
  questions: List[Question]
  answers: List[Answer]

  def __init__(self, header, questions, answers):
    self.header = header
    self.questions = questions
    self.answers = answers
    self.header.qdcount = len(questions)
    self.header.ancount = len(answers)

  @classmethod
  def from_bytes(cls, bytes):
    header, index_after_header = Header.from_bytes(bytes)
    byte_pointer = index_after_header
    questions = []
    for _ in range(header.qdcount):
      dns_question, index_after_question = Question.from_bytes(
          bytes[byte_pointer:]
      )
      byte_pointer = byte_pointer + index_after_question
      questions.append(dns_question)
    answers = []
    for _ in range(header.ancount):
      dns_answer, index_after_answer = Answer.from_bytes(
          bytes[byte_pointer:])
      byte_pointer = byte_pointer + index_after_answer
      answers.append(dns_answer)
    return cls(header, questions, answers)

  def to_bytes(self):
    result = self.header.to_bytes()
    for question in self.questions:
      result += question.to_bytes()
    for answer in self.answers:
      result += answer.to_bytes()
    return result

  @staticmethod
  def to_response_message(dns_message, new_answers):
    response_header = Header.to_response_header(dns_message.header)
    return Message(response_header, dns_message.questions, new_answers)
