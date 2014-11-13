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
import pestruct as ps
import copy
import pprint
pp = pprint.PrettyPrinter(indent=4)
from collections import OrderedDict

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
			"PEType" : "Unknow",
			"customFunctions" : {
				"peString" : peLengthLineRead,
				"peUninon" : peUninon
			}
		}
		self.options = dict(default_options.items() + options.items())
		self.validOptions()
		self.data = self.options["data"]
		if self.options["type"] == "file" :
			self.buildBuffer()
			try:
				self.simplePeTest()
			except :
				self.options["PEType"] = "none"

	def dataToBuffer(self,data,struct=False,fill="0"):
		if type(struct) is list:
			data = self.fillStructWithData(struct,data,fill)
		buff = ""
		for elem in data:
			if type(elem[1]) is str:
				buff = buff + swapLeBe(elem[1])
			elif type(elem[1]) is list:
				buff = self.dataToBuffer(elem[1])
			else:
				pass
		self.buffer = self.buffer + hexIt(buff)

	def writeBufferToFile(self,file):
		try:
			with open(file, "wb") as f:
				f.write(self.buffer.encode('hex'))
		except:
			pass

	def buildBuffer(self):
		if self.options["type"] == "file" :
			try:
				file = open(self.options["location"], "rb")
				self.buffer = file.read()
				file.close()
			except :
				debug_msg("1",-1)
		elif self.options["type"] == "new32" :
			self.buildNewWin32Buffer()
		else:
			debug_msg("0", -1)
	def fillBuffer(self,size,ttype="0"):
		tmp = ""
		if ttype == "rnd" \
		or ttype == "rnd+":
			tmp = getRandomHex(size)
		else:
			if ttype != "0":
				sizet = len(ttype)
				if sizet < size:
					size = size-sizet
				else:
					ttype = ttype[:size]
					size = 0
				tmp = ttype
			for i in range(size):
				tmp = tmp + "0"
		self.buffer = self.buffer + hexIt(tmp)


	def buildNewWin32Buffer(self, type="test"):

		pass

	def fillStructWithData(self, struct, data, fill = "0"):
		result = []
		for idx, val in enumerate(struct):
			if type(val[0]) is str:
				resolved = False
				for elem in data:
					if elem[0] == val[0]:
						if type(elem[1]) is str:
							size = val[1]*2
							length = len(elem[1])
							if length < size:
								tmp = elem[1]
								if fill == "rnd+":
									tmp = tmp + getRandomHex(size-length)
								else:
									for i in range(size-length):
										tmp = tmp + "0"
							else:
								tmp = elem[1][:size]
							result.append((val[0],tmp))
							resolved = True
						elif type(elem[1]) is list:
							if type(val[1]) is list:
								result.append((val[0],self.fillStructWithData(val[1],elem[1],fill)))
								resolved = True
							else: # error in data types
								pass
						else: # not suported type
							pass
				if not resolved:
					if type(val[1]) is int:
						tmp = ""
						size = val[1]*2
						if fill == "rnd" \
						or fill == "rnd+" :
							tmp = getRandomHex(size)
						else:
							for i in xrange(size):
								tmp = tmp + "0"
							if fill != "0":
								length = len(fill)
								if length > size:
									tmp = fill[:size]
								else:
									for i in range(size-length):
										tmp = tmp + "0"

						result.append((val[0],tmp))
					elif type(val[1]) is list:
						result.append((val[0],self.fillStructWithData(val[1],[],fill)))
			elif type(val[0]) is list:
				if type(val[1]) is list:
					tmp2 = []
					for name in val[1]:
						tmp2.append((name, copy.deepcopy(val[0])))
					for elem in self.fillStructWithData(tmp2,data,fill):
						result.append(elem)
				else: # not a list oO?
					pass
			else: #not known
				pass
		return result
					


	def simplePeTest(self):
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
		somedata = [
			("e_magic","5a4d"),
			("e_lfanew", "00ffeeddccbbaa99887766"),
			("_IMAGE_FILE_HEADER",[
				("test","ab"),
				("test2",[
					("_name",[
						("subnested2","1337")
					])
				])
			])
		]
		firstdata = [
			("e_magic","5a4d"),
			("e_lfanew", "00000040")
		]
		seconddata = [
			("Signature" , "00004550"), # pe magic
			("_IMAGE_FILE_HEADER" , [ # FileHeader
				("Machine", 2),
				("NumberOfSections", 2),
				("TimeDateStamp", 4),
				("PointerToSymbolTable", 4),
				("NumberOfSymbols", 4),
				("SizeOfOptionalHeader", 2),
				("Characteristics", 2)
			]),
			("_Image_Optional_HEADER", [ #OptionalHeader
				( "Magic", 2),
				( "MajorLinkerVersion", 1),
				( "MinorLinkerVersion", 1),
				( "SizeOfCode", 4),
				( "SizeOfInitializedData", 4), 
				( "SizeOfUninitializedData", 4 ),
				( "AdressOfEntryPoint", 4), 
				( "BaseOfCode", 4),
				( "ImageBase", 8), 
				( "SectionAlignment", 4), 
				( "FileAlignement", 4), 
				( "MajorOperatingSystemVarsion", 2 ),
				( "MinorOperatingSystemVersion", 2 ),
				( "MajorImageVersion", 2 ),
				( "MinorImageVersion", 2 ),
				( "MajorSubsystemVersion", 2 ),
				( "MinorSubsystemVersion", 2 ),
				( "Win32VersionValue", 4 ),
				( "SizeOfImage", 4 ),
				( "SizeOfHEaders", 4 ),
				( "CheckSum", 4 ),
				( "Subsystem", 2 ),
				( "DllCharacteristics", 2),
				( "SizeOfStackReserve", 8),
				( "SizeOfStackCommit", 8),
				( "SizeOfHeapReserve", 8),
				( "SizeOfHeapCommit", 8),
				( "LoaderFlags", 4),
				( "NumberOfRvaAnSizes", 4),
				([ 
					("VirtualAdress" , 4),
					("Size" , 4)
				],
				[
					"_IMAGE_DATA_DIRECTORY_ENTRY_EXPORT",
					"_IMAGE_DATA_DIRECTORY_ENTRY_IMPORT",
					"_IMAGE_DATA_DIRECTORY_ENTRY_RESOURCE",
					"_IMAGE_DATA_DIRECTORY_ENTRY_EXCEPTION",
					"_IMAGE_DATA_DIRECTORY_ENTRY_SECURITY",
					"_IMAGE_DATA_DIRECTORY_ENTRY_BASERELOC",
					"_IMAGE_DATA_DIRECTORY_ENTRY_DEBUG",
					"_IMAGE_DATA_DIRECTORY_ENTRY_COPYRIGHT",
					"_IMAGE_DATA_DIRECTORY_ENTRY_GLOBALPTR",
					"_IMAGE_DATA_DIRECTORY_ENTRY_TLS",
					"_IMAGE_DATA_DIRECTORY_ENTRY_LOAD_CONFIG",
					"_IMAGE_DATA_DIRECTORY_ENTRY_BOUND_IMPORT",
					"_IMAGE_DATA_DIRECTORY_ENTRY_IAT",
					"_IMAGE_DATA_DIRECTORY_ENTRY_DELAY_IMPORT",
					"_IMAGE_DATA_DIRECTORY_ENTRY_COM_DESCRIPTOR",
					"_IMAGE_DATA_DIRECTORY_ENTRY_RESERVED"
				])
			])
		]
		#dh = self.fillStructWithData(ps._IMAGE_DOS_HEADER, firstdata)
		#dh, offset =  self.fillStruct(ps._IMAGE_DOS_HEADER)
		#pp.pprint(dh)
		self.dataToBuffer(firstdata,ps._IMAGE_DOS_HEADER,"0")
		self.fillBuffer(64-len(self.buffer),"rnd")
		self.dataToBuffer(seconddata,ps._IMAGE_NT_HEADERS_32p,"0")
		pp.pprint(self.buffer)
		#self.fillBuffer(4096-len(self.buffer),"rnd")
		self.writeBufferToFile("test.bin")
		'''
		dh, offset =  self.fillStruct(ps._IMAGE_DOS_HEADER)
		offset = int(self.get(dh,"e_lfanew"),16)
		ts, offset =  self.fillStruct(ps._TEST_STRUCT)
		if self.options["PEType"] == "32p" :
			nth , offset = self.fillStruct(ps._IMAGE_NT_HEADERS_32p, offset)
		else:
			nth , offset = self.fillStruct(ps._IMAGE_NT_HEADERS_32, offset)
		pp.pprint(dh)
		pp.pprint(nth)
		pp.pprint(ts)
		pp.pprint(dh)
		'''
		return True

	def validOptions(self):
		op = self.options
		if type(op["data"]) is not str \
		or type(op["type"]) is not str \
		or type(op["location"]) is not str :
			debug_msg("2",-1)

	def get(self,struct,name):
		if type(name) is not str:
			return False
		for item in struct:
			if item[0] == name:
				return item[1]
		return False

	def fillStruct(self,struct,offset=0):
		struct_offset = offset
		result = []
		for idx, obj in enumerate(struct) :
			if type(obj) is tuple : 
				if len(obj) == 2 :
					if type(obj[0]) is str :
						if type(obj[1]) is int :
							tmp = struct_offset + obj[1]
							result.append((obj[0],bleStrToHex(self.buffer[struct_offset:tmp])))
							struct_offset = tmp
						elif type(obj[1]) is list:
							tmp, struct_offset = self.fillStruct(obj[1],struct_offset)
							result.append((obj[0],tmp))
						else: # not last node
							pass
					else: #not starting with str
						if type(obj[0]) is list :
							if type(obj[1]) is list:
								for elem in obj[1] :
									tmp, struct_offset = self.fillStruct(obj[0],struct_offset)
									result.append((elem,tmp))
							else: # starting with list but not the second
								pass
						else: # not starting with list neither str
							pass
						pass
				else: #not length 2 
					pass
			else: # not a tuple
				pass
		return result, struct_offset
		'''
		pp.pprint(struct)
		quit()
		if type(struct) is dict:
			struct = OrderedDict(struct)
		if type(struct) is not OrderedDict:
			print type(struct)
			debug_msg("3",-1)
		struct_offset = offset
		tail = {}
		for idx, val in struct.items() :
			if type(val) is int:
				tmp = struct_offset + val
				struct[idx] = bleStrToHex(self.buffer[struct_offset:tmp])
				struct_offset = tmp
			elif type(val) is dict:
				struct[idx], struct_offset = self.fillStruct(val,struct_offset)
			elif type(val) is tuple:
				if type(val[0]) is dict:
					tmp = {"0":copy.deepcopy(val[0])}
					for name in val[1:]:
						tmp[name] = copy.deepcopy(val[0])
					#print tmp
					tmp , struct_offset = self.fillStruct(tmp,struct_offset)
					struct[idx] = copy.deepcopy(tmp["0"])
					del tmp["0"]
					#print tmp
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
		'''

	def callStructCustom(self,options,struct_offset):
		try:
			return self.options["customFunctions"][options[0]](self,options[1:],struct_offset)
		except:
			debug_msg("9",-1)


