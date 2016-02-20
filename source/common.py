# -*- coding: utf-8 -*-

"""
common.py
---------

Utilites used by multiple examples.
"""

import os
import sys
import signalfd
import socket
import select

if 'EPOLLRDHUP' not in dir(select):
	select.EPOLLRDHUP = 0x2000

from errno import EAGAIN, EWOULDBLOCK, EINTR, ENOBUFS, EPIPE
from signal import SIGHUP, SIGINT, SIGQUIT, SIGABRT, SIGTERM
from signalfd import SFD_NONBLOCK, SFD_CLOEXEC, SIG_BLOCK
from select import EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLRDHUP, EPOLLHUP, EPOLLONESHOT, EPOLL_CLOEXEC

shutdown_signals = {SIGHUP, SIGINT, SIGQUIT, SIGABRT, SIGTERM}

def close_socket(sock, how=socket.SHUT_RDWR):
	"""
	Closes ``sock`` after calling ``shutdown``, so that processes using the other end know that
	we are no longer listening.
	"""

	if sock is None:
		return

	try:
		sock.shutdown(how)
	except:
		pass

	sock.close()

class MessageSender:
	def __init__(self, msg, sock):
		self.msg = msg
		self.sock = sock
		self.total_sent = 0

	def fileno(self):
		return self.sock.fileno()

	def __iter__(self):
		return self

	def __next__(self):
		while True:
			while self.total_sent != len(self.msg):
				try:
					sent = self.sock.send(self.msg[self.total_sent:])
				except OSError as e:
					if e.errno in {EAGAIN, EWOULDBLOCK, EINTR, ENOBUFS}:
						return
					elif e.errno == EPIPE:
						raise BrokenPipeError("Connection closed.")

				if sent == 0:
					raise BrokenPipeError("Connection closed.")
				self.total_sent = self.total_sent + sent

			self.total_sent = 0
			return

def check_signal(sig_fd, event):
	if event & EPOLLIN:
		si = signalfd.read_siginfo(sig_fd)
		sig = si.ssi_signo

		if sig not in shutdown_signals:
			print("Unexpected signal {}.".format(sig), file=sys.stderr, flush=True)
		else:
			raise SystemExit(sig)
	else:
		print("Unexpected event {:#x} for signal FD.".format(event), file=sys.stderr,
			flush=True)

def poll_events(sender, sig_fd, epoll):
	register = False

	while True:
		if register:
			events = epoll.poll(timeout=0.5)
			epoll.modify(sender.sock, EPOLLOUT | EPOLLRDHUP | EPOLLONESHOT)
			register = False
		else:
			events = epoll.poll()

		for fd, event in events:
			if fd == sender.fileno():
				# Even if we get EPOLLRDHUP or EPOLLHUP, there may be unread data.
				if event & (EPOLLOUT | EPOLLERR | EPOLLRDHUP | EPOLLHUP):
					next(sender)
					register = True
				else:
					print("Unexpected event {:#x} for socket FD.".format(event),
						file=sys.stderr, flush=True)
			elif fd == sig_fd:
				check_signal(sig_fd, event)
			else:
				print("Unexpected FD {} obtained from epoll.".format(fd),
					file=sys.stderr, flush=True)

def send_message(msg, dst):
	"""
	Repeatedly transmits the message ``msg`` to the address ``dst`` (an address-port tuple).
	"""

	sig_fd = signalfd.signalfd(-1, shutdown_signals, SFD_NONBLOCK | SFD_CLOEXEC)
	signalfd.sigprocmask(SIG_BLOCK, shutdown_signals)
	sock, epoll = None, None

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect(dst)
		sock.setblocking(False)
		sender = MessageSender(msg, sock)

		epoll = select.epoll(sizehint=2, flags=EPOLL_CLOEXEC)
		epoll.register(sig_fd, EPOLLIN)
		epoll.register(sock, EPOLLOUT | EPOLLRDHUP | EPOLLONESHOT)

		print("Started sending.", file=sys.stderr, flush=True)
		poll_events(sender, sig_fd, epoll)
	except BrokenPipeError as e:
		print(str(e), file=sys.stderr, flush=True)
	except SystemExit as e:
		print("Terminated.", file=sys.stderr, flush=True)
		raise
	finally:
		if epoll:
			epoll.close()

		os.close(sig_fd)
		close_socket(sock)
		print("Stopped sending.", file=sys.stderr, flush=True)
