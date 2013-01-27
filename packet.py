# -*- coding: utf-8 -*-

import struct
import socket
import re

class Packet:
	'''
	Basic packet-class for SVIFFR.
	'''
	def __init__(self, packed_data):
		'''
		Init packet object.
		'''
		self.DATA = struct.unpack('!BBHHHBBH4s4s', packed_data[:20])
		
		self.VERSION = self.DATA[0] >> 4
		self.IHL = self.DATA[0] & 0xF
		self.TOS = self.DATA[1]
		self.TOTAL_LENGTH = self.DATA[2]
		self.ID = self.DATA[3]
		self.FLAGS = self.DATA[4]
		self.FRAGMENT_OFFSET = self.DATA[4] & 0x1FFF
		self.TTL = self.DATA[5]
		self.PROTOCOL_NR = self.DATA[6]
		self.CHECKSUM = self.DATA[7]
		self.SOURCE_ADDR = socket.inet_ntoa(self.DATA[8])
		self.DESTINATION_ADDR = socket.inet_ntoa(self.DATA[9])
		self.PAYLOAD = packed_data[20:]
		# if protocol is tcp
		if self.PROTOCOL_NR == 6:
			tcp_header = packed_data[self.IHL*4:self.IHL*4+20]
			self.TCP_DATA = tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
			self.SOURCE_PORT = self.TCP_DATA[0]
			self.DESTINATION_PORT = self.TCP_DATA[1]
			self.SEQUENCE = self.TCP_DATA[2]
			self.ACKNOWLEDGEMENT = self.TCP_DATA[3]
			self.DOFF_RESERVED = self.TCP_DATA[4]
			self.TCP_LENGTH = self.DOFF_RESERVED >> 4
			self.HEADER_SIZE = self.IHL*4 + self.TCP_LENGTH*4
			self.TCP_DATA = packed_data[self.HEADER_SIZE:]
		
	def get_tos(self, data):
		'''
		Filter types of service from the given data.
		'''
		precedence = {0: "Routine",
					  1: "Priority",
                      2: "Immediate",
                      3: "Flash",
                      4: "Flash override",
                      5: "CRITIC/ECP",
                      6: "Internetwork control",
                      7: "Network control"}
		delay = {0: "Normal delay",
                 1: "Low delay"}
		throughput = {0: "Normal throughput",
                      1: "High throughput"}
		reliability = {0: "Normal reliability",
                       1: "High reliability"}
		cost = {0: "Normal monetary cost",
                1: "Minimize monetary cost"}   
        
		D = (data & 0x10) >> 4
		T = (data & 0x8) >> 3
		R = (data & 0x4) >> 2
		M = (data & 0x2) >> 1
        
		tabs = '\n\t\t\t'
		tos = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
              reliability[R] + tabs + cost[M]
		return tos
        
	def get_flags(self, data):
		'''
		Filter network flags from the given data.
		'''
		flag_R = {0: "0 - Reserved bit"}
		flag_DF = {0: "0 - Fragment if necessary",
                   1: "1 - Do not fragment"}
		flag_MF = {0: "Last fragment",
                   1: "More fragments"}
        
		R = (data & 0x8000) >> 15
		DF = (data & 0x4000) >> 14
		MF = (data & 0x2000) >> 13
        
		tabs = "\n\t\t\t"
		flags = flag_R[R] + tabs + flag_DF[DF] + tabs + flag_MF[MF]
		return flags
        
	def get_protocol(self, proto_nr):
		'''
		Specify the protocol from the given protocol number.
		'''
		proto_file = open("protocols.txt", 'r')
		proto_data =proto_file.read()
		protocol = re.findall(r'\n' + str(proto_nr) + ' (?:.)+\n', proto_data)
		if protocol:
			# Remove '\n's, leading whitespaces and protocol number 
			return protocol[0].replace('\n', '').replace(str(proto_nr), '').lstrip()
		else:
			return "No such protocol."
            
	def print_packet_info(self):
		'''
		Print packet information in a pretty-readable form.
		'''
		print("An IP packet with the size %i was captured." % self.TOTAL_LENGTH)
		print("\n-- Parsed data --")
		print("Version:\t\t" + str(self.VERSION))
		print("Header-Length:\t\t" + str(self.IHL*4) + " bytes")
		print("Type of Service:\t" + self.get_tos(self.TOS))
		print("Length:\t\t\t" + str(self.TOTAL_LENGTH))
		print("ID:\t\t\t" + str(hex(self.ID)) + " (" + str(self.ID) + ")")
		print("Flags:\t\t\t" + self.get_flags(self.FLAGS))
		print("Fragment offset:\t" + str(self.FRAGMENT_OFFSET))
		print("TTL:\t\t\t" + str(self.TTL))
		print("Protocol:\t\t" + self.get_protocol(self.PROTOCOL_NR))
		print("Checksum:\t\t" + str(self.CHECKSUM))
		print("Source:\t\t\t" + self.SOURCE_ADDR)
		print("Destination:\t\t" + self.DESTINATION_ADDR)
		print("Payload:\n" + str(self.PAYLOAD) + '\n')

