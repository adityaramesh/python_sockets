# -*- coding: utf-8 -*-

"""
many_to_one_echo.py
-------------------

Implements a simple, many-to-one communication channel involving multiple clients and one server.
The server simply echoes all of the data that it sent to it.

Study the example here: http://linux.die.net/man/4/epoll

TODO: three approaches:
- select
- epoll
"""

import os
import sys
import errno
import socket

from argparse import ArgumentParser
from threading import Barrier, Event, Lock, Thread, BrokenBarrierError

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from source.common import *

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
	loop_message(msg, args)

def listen(init_barr, term_cond, new_conn_list, new_conn_list_lock):
	"""
	Listens for incoming connections and adds them to ``new_conn_list``.
	"""

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setblocking(False)
		sock.bind((socket.gethostname(), SERVER_PORT))
		sock.listen(SERVER_BACKLOG_SIZE)
		print("Listening on {}:{}.".format(socket.gethostname(), SERVER_PORT),
			file=sys.stderr)
	except:
		"""
		If something went wrong during initialization, we clean up, abort the barrier, and
		allow the other worker to terminate.
		"""
		term_cond.set()
		init_barr.abort()
		close_socket(sock)
		raise

	try:
		init_barr.wait()

		while not term_cond.is_set():
			try:
				(conn, addr) = sock.accept()
				conn.setblocking(False)
			except OSError as e:
				if e.errno not in [errno.EAGAIN, errno.EWOULDBLOCK]:
					raise
			else:
				with new_conn_list_lock:
					new_conn_list.append((conn, addr))
	except BrokenBarrierError:
		"""
		If we got here beacuse the other worker broke the barrier, then we suppress the
		exception, since it is not relevant to what actually went wrong.
		"""
		pass
	finally:
		term_cond.set()
		close_socket(sock)

		with new_conn_list_lock:
			for conn, _ in new_conn_list:
				close_socket(conn)

		print("Stopping listening.", file=sys.stderr, flush=True)

def drain(conn, msg_buf):
	"""
	Reads a chunk of data from the connection ``conn``, and returns whether the ``conn`` is
	still open.
	"""

	count = 0

	try:
		count = conn.recv_into(msg_buf)
	except OSError as e:
		if e.errno in [errno.EAGAIN, errno.EWOULDBLOCK, errno.EBADF]:
			return True
		else:
			raise
	else:
		if count != 0:
			print(msg_buf[:count].decode('utf-8'), end='', flush=True)
			return True
		else:
			close_socket(conn)
			return False

def echo(init_barr, term_cond, new_conn_list, new_conn_list_lock):
	try:
		conn_list = []
		msg_buf = bytearray(SERVER_BUFFER_SIZE)
	except:
		"""
		We do not want the other worker to deadlock if we get an out-of-memory error. If
		this happens, we abort the barrier so that it has an opportunity to exit.
		"""
		init_barr.abort()
		raise

	try:
		init_barr.wait()

		while not term_cond.is_set():
			conn_list[:] = [(conn, addr) for (conn, addr) in conn_list if
				drain(conn, msg_buf)]

			if len(new_conn_list) != 0:
				with new_conn_list_lock:
					conn_list.extend(new_conn_list)
					new_conn_list.clear()
	except BrokenBarrierError:
		pass
	finally:
		term_cond.set()
		for (conn, _) in conn_list:
			close_socket(conn)

def run_server(args):
	new_conn_list = []

	"""
	Used to allow the workers to wait for one another to initialize before proceeding.
	"""
	init_barr = Barrier(2)

	"""
	Used to coordinate shutdown among workers in case something goes wrong, or to initiate
	shutdown from the main thread if we receive an appropriate signal.
	"""
	term_cond = Event()
	new_conn_list_lock = Lock()

	args = (init_barr, term_cond, new_conn_list, new_conn_list_lock)
	listen_thread = Thread(target=listen, args=args)
	echo_thread = Thread(target=echo, args=args)

	def join():
		for thread in [listen_thread, echo_thread]:
			if thread.is_alive():
				thread.join()

	@on_shutdown
	def shutdown(signum, frame):
		term_cond.set()
		join()

	for thread in [listen_thread, echo_thread]:
		thread.start()

	"""
	The ``threading`` module calls ``join`` on all non-daemon threads after the main
	thread exits, so we do not need to do it here.
	"""

if __name__ == '__main__':
	args = parse_args()
	{'client': run_client, 'server': run_server}[args.role](args)
