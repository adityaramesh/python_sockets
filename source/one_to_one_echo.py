# -*- coding: utf-8 -*-

"""
one_to_one_echo.py
------------------

Implements a simple, one-way communication channel between a client and the server. The server
echoes all of the data that it sent to it.
"""

import os
import sys
import socket

from argparse import ArgumentParser

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from source.common import *

def parse_args():
	parser = ArgumentParser("Opens a one-way communication channel from a client to a server.")
	parser.add_argument('--role', type=str, choices=['client', 'server'], required=True)
	parser.add_argument('--server_address', type=str)
	args = parser.parse_args()

	if args.role == 'client' and args.server_address is None:
		raise ValueError("Clients must provide the 'server_address' argument.")
	return args

def run_client(args):
	msg = "Hi I love you.\n".encode('utf-8')
	loop_message(msg, args)

def run_server(args):
	sock = None
	conn = None
	listening = False

	def cleanup(signum=None, frame=None):
		close_socket(sock)
		close_socket(conn)

		if listening:
			print("Stopped listening.", file=sys.stderr, flush=True)
		if signum is not None:
			sys.exit(1)

	@safely_invoke(on_shutdown=cleanup, catch_signals=True)
	def loop():
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind((socket.gethostname(), SERVER_PORT))

		"""
		The backlog bounds the rate at which the server can accept new TCP connections. In
		order to establish a connection with the server, a client must perform a three-way
		handshake (SYN, ACK, SYN-ACK). Assuming that the server can perform the handshake
		for ``backlog`` connections simultaneously, the maximum rate at which new
		connections can be established is given by ``backlog / roundtrip_time``, where
		``roundtrip_time`` is the time necessary to perform the handshake. If ``backlog``
		conenctions are in flight and the server receives a new ACK request, then it will be
		rejected.

		Setting this value too low can drastically reduce the performace of web servers. The
		kernel usually puts a cap of 128 on the backlog.

		Since this is a one-to-one commnunication channel, we just set the backlog to one.
		"""
		sock.listen(1)

		listening = True
		print("Listening on {}:{}.".format(socket.gethostname(), SERVER_PORT),
			file=sys.stderr)

		conn, _ = sock.accept()
		msg_buf = bytearray(SERVER_BUFFER_SIZE)

		while True:
			count = conn.recv_into(msg_buf)
			if count == 0:
				print("Connection closed.", file=sys.stderr, flush=True)
				cleanup()
				return
			print(msg_buf[:count].decode('utf-8'), end='', flush=True)

if __name__ == '__main__':
	args = parse_args()
	{'client': run_client, 'server': run_server}[args.role](args)
