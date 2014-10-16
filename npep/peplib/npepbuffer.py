#!/usr/bin/env python2.7
# -*- coding: utf-8 -*- 

'''---------------------------------------------------------------------------|
                                                              _____           |
      Autor: Notsgnik                                       /||   /           |
      Email: Labruillere gmail.com                         / ||  /            |
      website: notsgnik.github.io                         /  || /             |
      License: GPL v3                                    /___||/              |
      																		  |
---------------------------------------------------------------------------!'''

from disutil import *
import copy

def peLengthLineRead(binObj,var,offset):
	if type(var[0]) is not int:
		debug_msg("12", -1)
	length = bleStrToInt(binObj.buffer[offset-var[0]:offset])
	string = binObj.buffer[offset:offset+length]
	return string, offset + length, {}

def peUninon(binObj,var,offset):
	'''
		not really union since an edit dont affect others entries and type are not relevent either
	'''
	if type(var[0]) is not int:
		debug_msg("12", -1)
	value = binObj.buffer[offset:offset+var[0]]
	tmp = {}
	for elem in var[1:]:
		if type(elem) is not str:
			debug_msg("11", -1)
		tmp[elem] = value
	return value, offset + var[0], tmp

class BinaryBuffer():
	"""docstring for BinaryBuffer"""
	def __init__(self, options = {}):
		default_options = {
			"type" : "file",
			"data" : "",
			"location": "",
			"NT" : False,
			"PEType" : "32",
			"customFunctions" : {
				"peString" : peLengthLineRead,
				"peUninon" : peUninon
			}
		}
		self.options = dict(default_options.items() + options.items())
		self.validOptions()
		self.data = self.options["data"]
		self.buildBuffer()
		self.validPeSimple()

	def buildBuffer(self):
		if self.options["type"] == "file" :
			try:
				file = open(self.options["location"], "rb")
				self.buffer = file.read()
				file.close()
			except :
				debug_msg("1",-1)
		else:
			debug_msg("0", -1)

	def validPeSimple(self):
		b = self.buffer
		if b[0:2] != "MZ":
			debug_msg("5",-1)
		pe_offset = bleStrToInt(b[60:64])
		if pe_offset > 0:
			self.options["NT"] = True
			pe_optional_header_size = bleStrToInt(b[pe_offset + 20:pe_offset + 22])
			if pe_optional_header_size <= 0:
				 debug_msg("6",-1)
			pe_magic = bleStrToHex(b[pe_offset + 24:pe_offset + 26])
			if pe_magic == "010b":
				self.options["PEType"] = "32"
			elif pe_magic == "020b":
				self.options["PEType"] = "32p"
			else:
				debug_msg("7",-1)




	def sayHello(self):
		#debug_msg("1",-2)
		print bleStrToHex(self.buffer[0:2])
		print bleStrToHex(self.buffer[472:480])
		return True

	def validOptions(self):
		op = self.options
		if type(op["data"]) is not str \
		or type(op["type"]) is not str \
		or type(op["location"]) is not str :
			debug_msg("2",-1)

	def fillStruct(self,struct,offset=0):

		if type(struc) is not dict:
			debug_msg("3",-1)
		struct_offset = offset
		tail = {}
		for idx, val in struct.items() :
			if type(val) is int:
				tmp = struct_offset + val
				struct[idx] = self.buffer[struct_offset:tmp]
				struct_offset = tmp
			elif type(val) is dict:
				struct[idx], struct_offset = self.fillStruct(val,struct_offset)
			elif type(val) is list:
				if type(val[0]) is dict:
					tmp = {}
					for name in val[1:]:
						tmp[name] = copy.deapcopy(val[0])
					tmp , struct_offset = self.fillStruct(tmp,struct_offset)
					tail = dict(tmp.items() + tail.items())
				elif type(val[0]) is str:
					try:
						struct[idx], struct_offset, tmp = self.callStructCustom(val[1:],struct_offset)
						tail = dict(tmp.items() + tail.items())
					except:
						debug_msg("10",-1)
				else:
					debug_msg("8",-1)
			else:
				debug_msg("4",-1)
		struct = dict(struct.items() + tail.items())
		return struct, struct_offset

	def callStructCustom(self,options,struct_offset):
		try:
			return self.options["customFunctions"][options[0]](self,options[1:],struct_offset)
		except:
			debug_msg("9",-1)


