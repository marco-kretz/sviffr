# -*- coding: utf-8 -*-

import socket
import sys
import packet
import threading
from datetime import datetime, time

class Sviffr(threading.Thread):
	'''
	Basic class for sniffing and filtering network-packets.
	'''
	def __init__(self, protocol):
		'''
		Init Sviffr object.
		'''
		threading.Thread.__init__(self)
		if protocol in ['tcp', 'udp']:
			if protocol == 'tcp':
				self.SOCKET = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
			elif protocol == 'udp':
				self.SOCKET = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
		self.SNIFFING = False

	def run(self):
		'''
		Start sniffing process.
		'''
		self.SNIFFING = True
		while(self.SNIFFING):
			data = self.recieve_data(self.SOCKET)
			if data:
				p = packet.Packet(data)
				p.print_packet_info()

	def stop_sniffing(self):
		self.SNIFFING = False
        
	def recieve_data(self, s):
		data = ''
		try:
			data = s.recvfrom(65565)
		except s.timeout:
			data = ''
		except:
			print("An error occured.")
			sys.exc_info()
		return data[0]
