import socket
import random
from typing import List
from app.models.answer import Answer
from app.models.message import Message


class Resolver:
  def __init__(self, resolver):
    self.ip = resolver[0]
    self.port = resolver[1]
    if resolver:
      # If the resolver address is provided, create a socket to that resolver.
      self.resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  def forward_questions(self, dns_message: Message) -> List[Answer]:
    if not self.ip and not self.port:
      raise RuntimeError("IP and port required")
    # Iterate over each question and query for each request
    # Offset used to only parse the answer sections for each response
    questions = dns_message.questions
    answers = []
    # Construct a new DNS packet for each question with the same headers
    print("forward_questions", f"There are {len(questions)} to forward")
    for question in questions:
      new_message = Message(dns_message.header, [question], [])
      sub_request_response = self._forward(new_message.to_bytes())
      sub_response_message = Message.from_bytes(sub_request_response)
      print("forward_questions", f"Received message {sub_response_message}")
      if len(sub_response_message.answers) > 0:
        answers.extend(sub_response_message.answers)
      else:
        answers.append(Answer(question.name))
    if self.resolver_socket:
      self.resolver_socket.close()
    return answers

  def resolve_questions(self, dns_message: Message) -> List[Answer]:
    questions = dns_message.questions
    answers = []
    for question in questions:
      answers.append(Answer(question.name))
    return answers

  def _forward(self, message: bytes) -> bytes:
    try:
      self.resolver_socket.sendto(message, (self.ip, self.port))
      buf, source = self.resolver_socket.recvfrom(512)
      return buf
    except Exception as e:
      raise RuntimeError(
          f"Unable to forward request to server: {e}", (self.ip, self.port)
      )
