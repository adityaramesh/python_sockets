# -*- coding: utf-8 -*-

"""
common.py
---------

Utilites used by mulitple examples.
"""

def send(msg, sock):
	total_sent = 0
	while total_sent != len(msg):
		sent = sock.send(msg[total_sent:])
		if sent == 0:
			raise BrokenPipeError()
		total_sent = total_sent + sent
