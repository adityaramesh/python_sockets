# -*- coding: utf-8 -*-

"""
common.py
---------

Utilites used by mulitple examples.
"""

import sys
import time
import errno
import signal
import socket

SERVER_PORT         = 7700
SERVER_BACKLOG_SIZE = 5
SERVER_BUFFER_SIZE  = 4096

def on_shutdown(handler):
	"""
	Registers a handler with all of the signals that are expected to initiate program shutdown.
	The handler should be reentrant-safe.
	"""

	for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM]:
		signal.signal(sig, handler)

	return handler

def safely_invoke(on_shutdown, catch_signals=False):
	"""
	Invokes a function ``func`` safely, so that resources are released by ``on_shutdown`` in the
	event that an unexpected exception (or signal if ``catch_signals=True``) is caught.  Known
	exceptions should still be caught and handled by ``func`` in case they should be serviced by
	performing an action other than invoking ``on_shutdown``.

	Args:
		on_shutdown: Binary function registered as the signal handler. This function should
			release any resources allocated by ``func``.

		catch_signals: If true, registers ``on_shutdown`` as a signal handler using
			``on_shutdown``. In this case, ``on_shutdown`` should be reentrant-safe, and
			is not guaranteed to have thread-safe access to shared resources (as pthread
			does not provide any guarantees on synchronization primitives while they are
			used in signal handlers).

			Note that when using the ``threading`` module, only the main thread receives
			signals. So spawned threads should not need to register signal handlers
			unless they are daemons.
	"""

	def inner_decorator(func):
		if catch_signals:
			globals()['on_shutdown'](on_shutdown)

		try:
			func()
		except (KeyboardInterrupt, InterruptedError, SystemExit):
			# The signal handler will already call ``shutdown`` for us.
			assert catch_signals
			raise
		except:
			on_shutdown(None, None)
			raise

	return inner_decorator

def close_socket(sock, how=socket.SHUT_RDWR):
	"""
	In order to correctly close a socket, we must first call ``shutdown``, and then call
	``close``, regardless of whether the former call succeeded. This function is reentrant-safe.
	"""

	if sock is None:
		return

	try:
		sock.shutdown(how)
	except:
		pass

	try:
		sock.close()
	except:
		pass

def send(msg, sock):
	"""
	Transmits ``msg`` using ``sock``, and returns after ``msg`` has been sent.
	"""

	total_sent = 0

	while total_sent != len(msg):
		sent = sock.send(msg[total_sent:])
		if sent == 0:
			raise BrokenPipeError()
		total_sent = total_sent + sent

def loop_message(msg, args):
	"""
	Repeatedly transmits the message ``msg`` to the server whose address is given by ``args``.
	"""

	sock = None
	connected = False

	def cleanup(signum=None, frame=None):
		close_socket(sock)

		if connected:
			print("Stopped sending.", file=sys.stderr, flush=True)
		if signum is not None:
			sys.exit(1)

	@safely_invoke(on_shutdown=cleanup, catch_signals=True)
	def loop():
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((args.server_address, SERVER_PORT))

			connected = True
			print("Started sending.", file=sys.stderr, flush=True)

			while True:
				send(msg, sock)
				time.sleep(0.5)
		except OSError as e:
			if e.errno in [errno.EBADF, errno.EPIPE]:
				print("Connection closed.", file=sys.stderr)
			else:
				raise
