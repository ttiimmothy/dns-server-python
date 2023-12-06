import argparse
import socket
import traceback
from app.constants.resolver import Resolver
from app.models.message import Message


def main():
  udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_socket.bind(("127.0.0.1", 2053))
  args = parse_args()
  print("CLI Arguments", args)
  while True:
    try:
      buf, source = udp_socket.recvfrom(512)
      request_dns_message = Message.from_bytes(buf)
      print("Received request dns_message", request_dns_message)
      answers = []
      if args.resolver:
        resolver = Resolver(args.resolver)
        answers = resolver.forward_questions(request_dns_message)
      else:
        resolver = Resolver()
        answers = resolver.resolve_questions(request_dns_message)
      response_dns_message = Message.to_response_message(
          request_dns_message, answers
      )
      response = response_dns_message.to_bytes()
      udp_socket.sendto(response, source)
    except Exception as e:
      print(f"Error receiving data: {e}")
      traceback.print_exc()
      break


def resolver_address(address):
  try:
    ip, port = address.split(":")
    port = int(port)
    return (ip, port)
  except e:
    raise argparse.ArgumentError(
        "Resolver address needs to be in the form <IP>:<PORT>"
    )


def parse_args():
  parser = argparse.ArgumentParser(
      description="IP and port of DNS resolution server")
  parser.add_argument(
      "--resolver",
      type=resolver_address,
      help="Resolver address needs to be in the form <IP>:<PORT>",
  )
  return parser.parse_args()


if __name__ == "__main__":
  main()
