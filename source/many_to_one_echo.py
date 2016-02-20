# -*- coding: utf-8 -*-

"""
many_to_one_echo.py
-------------------------------

Implements a simple, many-to-one communication channel involving multiple clients and one server.
The server simply echoes all of the data that it sent to it.
"""

import os
import sys
import signalfd
import socket
import select

if 'EPOLLRDHUP' not in dir(select):
	select.EPOLLRDHUP = 0x2000

from signalfd import SFD_NONBLOCK, SFD_CLOEXEC, SIG_BLOCK
from select import EPOLLIN, EPOLLERR, EPOLLRDHUP, EPOLLHUP, EPOLL_CLOEXEC
from argparse import ArgumentParser

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from source.common import *
from source.settings import *

def parse_args():
	parser = ArgumentParser("Opens a many-to-one communication channel.")
	parser.add_argument('--role', type=str, choices=['client', 'server'], required=True)
	parser.add_argument('--name', type=str)
	parser.add_argument('--server_address', type=str)
	args = parser.parse_args()

	if args.role == 'client' and args.name is None:
		raise ValueError("Clients must provide the 'name' argument.")
	if args.role == 'client' and args.server_address is None:
		raise ValueError("Clients must provide the 'server_address' argument.")
	return parser.parse_args()

def run_client(args):
	msg = "Hi '{}' loves you.\n".format(args.name).encode('utf-8')
	send_message(msg, (args.server_address, SERVER_PORT))

def listen(sock, sig_fd, conn_dict, epoll):
	msg_buf = bytearray(SERVER_BUFFER_SIZE)

	while True:
		events = epoll.poll()

		for fd, event in events:
			if fd in conn_dict:
				if event & (EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP):
					"""
					Reading from the socket should really be done on another
					thread, to ensure responsiveness. A good way to do this
					would be using a work-stealing queue, but Python is a bad
					fit for this.
					"""
					try:
						conn, addr = conn_dict[fd]
						read(conn, msg_buf)
					except BrokenPipeError:
						conn_dict.pop(fd)
						epoll.unregister(conn)
						close_socket(conn)
						print("Connection from {} closed.".format(addr),
							file=sys.stderr, flush=True)
				else:
					print("Unexpected event {:#x} for connection FD.".
						format(event), file=sys.stderr, flush=True)
			elif fd == sock.fileno():
				if event & (EPOLLIN | EPOLLERR):
					addr = accept(sock)
					if addr:
						conn = addr[0]
						assert conn.fileno() not in conn_dict

						conn.setblocking(False)
						conn_dict[conn.fileno()] = addr
						epoll.register(conn.fileno(), EPOLLIN | EPOLLRDHUP)
				else:
					print("Unexpected event {:#x} for socket FD.".format(event),
						file=sys.stderr, flush=True)
			elif fd == sig_fd:
				check_signal(sig_fd, event)
			else:
				print("Unexpected FD {} obtained from epoll.".format(fd),
					file=sys.stderr, flush=True)

def run_server(args):
	"""
	It is important that we create the signal FD and block the signals before doing anything
	else. Otherwise, we may get interrupted partway during initialization, and the resources we
	have allocated thus far will not be released.
	"""
	sig_fd = signalfd.signalfd(-1, shutdown_signals, SFD_NONBLOCK | SFD_CLOEXEC)
	signalfd.sigprocmask(SIG_BLOCK, shutdown_signals)

	sock, epoll = None, None
	conn_dict = {}

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setblocking(False)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(('0.0.0.0', SERVER_PORT))

		epoll = select.epoll(sizehint=2, flags=EPOLL_CLOEXEC)
		epoll.register(sig_fd, EPOLLIN)
		epoll.register(sock, EPOLLIN)

		sock.listen(SERVER_BACKLOG_SIZE)
		print("Listening on {}:{}.".format(socket.gethostname(), SERVER_PORT),
			file=sys.stderr, flush=True)
		listen(sock, sig_fd, conn_dict, epoll)
	except SystemExit:
		print("Terminated.", file=sys.stderr, flush=True)
		raise
	finally:
		if epoll:
			epoll.close()

		os.close(sig_fd)
		if sock:
			close_socket(sock)
		for conn, _ in conn_dict.values():
			close_socket(conn)

if __name__ == '__main__':
	args = parse_args()
	{'client': run_client, 'server': run_server}[args.role](args)
