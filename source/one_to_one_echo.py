# -*- coding: utf-8 -*-

"""
one_to_one_echo.py
------------------

Implements a simple, one-way communication channel between a client and the server. The server
echoes all of the data that it sent to it.
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
from source.common import shutdown_signals, close_socket, accept, check_signal, send_message
from source.settings import *

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
	send_message(msg, (args.server_address, SERVER_PORT))

def poll_connection(sock, sig_fd, epoll):
	while True:
		events = epoll.poll()

		for fd, event in events:
			if fd == sock.fileno():
				if event & (EPOLLIN | EPOLLERR):
					addr = accept(sock)
					if addr:
						return addr
				else:
					print("Unexpected event {:#x} for socket FD.".format(event),
						file=sys.stderr, flush=True)
			elif fd == sig_fd:
				check_signal(sig_fd, event)
			else:
				print("Unexpected FD {} obtained from epoll.".format(fd),
					file=sys.stderr, flush=True)

def poll_data(conn, sig_fd, epoll):
	msg_buf = bytearray(SERVER_BUFFER_SIZE)

	while True:
		events = epoll.poll()

		for fd, event in events:
			if fd == conn.fileno():
				if event & (EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP):
					"""
					Reading from the socket should really be done on another
					thread, to ensure responsiveness. A good way to do this
					would be using a work-stealing queue, but Python is a bad
					fit for this.
					"""
					read(conn, msg_buf)
				else:
					print("Unexpected event {:#x} for connection FD.".
						format(event), file=sys.stderr, flush=True)
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
	sock, conn, epoll = None, None, None

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setblocking(False)

		"""
		Make the server accessible from all IPs assigned to this machine. SO_REUSEADDR
		makes it so that if another server is running on another IP with the same port, then
		``bind`` will still work. Of course, data sent to the other server's address will
		still routed to it instead of us.
		"""
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(('0.0.0.0', SERVER_PORT))

		epoll = select.epoll(sizehint=2, flags=EPOLL_CLOEXEC)
		epoll.register(sig_fd, EPOLLIN)
		epoll.register(sock, EPOLLIN)

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
		print("Listening on {}:{}.".format(socket.gethostname(), SERVER_PORT),
			file=sys.stderr, flush=True)

		addr = poll_connection(sock, sig_fd, epoll)
		sock.close()
		sock = None

		addr[0].setblocking(False)
		epoll.register(addr[0], EPOLLIN | EPOLLRDHUP)

		print("Stopped listening for new connections.", file=sys.stderr, flush=True)
		poll_data(addr[0], sig_fd, epoll)
	except BrokenPipeError as e:
		"""
		A connection being closed is not really an exceptional situation, so we just print
		the message rather than allow the interpreter to output the full stack trace.
		"""
		print(str(e), file=sys.stderr, flush=True)
	except SystemExit as e:
		print("Terminated.", file=sys.stderr, flush=True)
		raise
	finally:
		if epoll:
			epoll.close()

		os.close(sig_fd)
		if sock:
			close_socket(sock)

		close_socket(conn)

if __name__ == '__main__':
	args = parse_args()
	{'client': run_client, 'server': run_server}[args.role](args)
