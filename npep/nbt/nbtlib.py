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

import copy
import binascii
import pprint
pp = pprint.PrettyPrinter(indent=4)
import random
import string


def peLengthLineRead(binObj,var,offset):
	if type(var[0]) is not int:
		debug_msg("12", -1)
	length = bleStrToInt(binObj.buffer[offset-var[0]:offset])
	string = binObj.buffer[offset:offset+length]
	return string, offset + length, {}

def bleStrToInt(string):
	return int(byteStringToHexString_le(string),16)

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

msgs = {
	"0" : "type unandled by binary buffer",
	"1" : "cannot open the file",
	"2" : "buffer options are not valid",
	"3" : " [*] Cannot write file",
	"4" : "the option suplied is not supported",
	"5" : "invalid PE File",
	"6" : "invalid PE Optional Header Size",
	"7" : "invalid PE magic",
	"8" : "structure syntax error within a list",
	"9" : "unable to execute custom function",
	"10": "custom function ruturn garbage",
	"11": "uniun options take only strings",
	"12": "first option must be integer",
	"13": "unable to correctly parse struct or data" ,
	"14": "Unknow structure type",
	"15": "buffer string error",
	"16": "data in wrong format, maybe not unfolded",
	"17": " [*] Warning : no more buffer",
	"18": "cannot fill with this data",
	"19": " [*] warning : structure bigger than buffer (that's what she said)",
	"20": " [!] Error : invalid fill option",
	"21": " [!] Error : parse Error",
	"22": " [!] Error : Name should be a string element",
	"23": " [!] Error : Wrong format"
}
debug_lvl = 0
def debug_msg(msg_nb, lvl = 1):
	if msgs == {}:
		error = "Error " + msg_nb
	else:
		try:
			error =  msgs[msg_nb]
		except :
			error = "Unknow"
	if debug_lvl < 0 or lvl < 0:
		raise Exception(error)
	elif debug_lvl >= lvl:
		print error


class BinaryBuffer():
	"""docstring for BinaryBuffer"""
	def __init__(self, options = {}):
		default_options = {
			"type" : "file",
			"littleEdian" : True,
			"location": "",
			"customFunctions" : {
				"peString" : peLengthLineRead,
				"peUninon" : peUninon
			}
		}
		self.options = dict(default_options.items() + options.items())
		self.validOptions()
		self.buffer = self.hexIt("")
		self.bufferSize = 0

	def byteStringToHexString_le(self,byteStr,littleEdian=True,stripForm="Normal",upper=False):
		return self.byteStringToHexString(byteStr,stripForm,upper,littleEdian)

	def hexIt(self,data=""):
		# trun hex string ( 48656c6c6f20576f726c6421 ) into corresponding bytes "Hello World!" 
		if not self.testForHexOnly(data):
				data = binascii.b2a_hex(data)
		return binascii.a2b_hex(data)

	def testForHexOnly(self,data):
		if type(data) is not str:
			debug_msg("23",-1)
		for cmpa in data:
			found = False
			for cmpb in string.hexdigits:
				if cmpa == cmpb:
					found = True
			if not found:
				return False
		return True

	def swapLeBe(self,data=""):
		if type(data) is not str:
			debug_msg("23",-1)
		tmp = ""
		for i in xrange(len(data),0,-2):
			tmp = tmp + data[i-2:i]
		return tmp

	def byteStringToInt_le(self,data=""):
		return int(byteStringToHexString_le(data),16)

	def byteStringToInt(self,data=""):
		return int(byteStringToHexString(data),16)

	def byteStringToHexString(self,byteStr,stripForm="Normal",upper=False,littleEdian=False):
		if type(byteStr) is not str:
			debug_msg("23",-1)
		if not upper:
			stripf = "%02x"
		else:
			stripf = "%02X"
		if stripForm == "hex":
			stripf = "\\x" + stripf
		elif stripForm == "space":
			stripf += " "
		#return "{0:02x}".format(ord(x)) for x in byteStr
		if littleEdian:
			return ''.join( [ stripf % ord( x ) for x in byteStr[::-1] ] ).strip()
		return ''.join( [ stripf % ord( x ) for x in byteStr ] ).strip()

	def getPrintable(self,byteStr=""):
		return ''.join(filter(string.printable.__contains__, byteStr))

	def getRandomHex(self,size):
		return "".join([random.choice("0123456789abcdef") for n in xrange(size)])

	def printBuffer(self,localBuffer=False,stripForm="Normal",upper=False):
		if localBuffer == False:
			localBuffer = self.buffer
		result = self.byteStringToHexString(localBuffer,stripForm,upper)
		#print result
		return result

	def printStrings(self,localBuffer=False):
		if localBuffer == False:
			localBuffer = self.buffer
		result = self.getPrintable(localBuffer)
		#print result
		return result

	def unfoldStruct(self,struct):
		if type(struct) is not list:
			return [], 0, 0
		resultStruct = []
		totelem = 0
		size = 0
		for structElem in struct:
			if type(structElem[0]) is list:
				template , newSize , newElem = self.unfoldStruct(structElem[0])
				if type(structElem[1]) is not list:
					debug_msg("21",-1)
				for elem in structElem[1]:
					if type(elem) is str:
						resultStruct.append(copy.deepcopy((elem,template)))
						totelem += newElem
						size += newSize
			elif type(structElem[0]) is str:
				if type(structElem[1]) is tuple:
					template, newSize, newElem = self.callStructCustom(structElem[1],("unfolding"))
					resultStruct.append(copy.deepcopy((structElem[0],template)))
					totelem += newElem
					size += newSize
				elif type(structElem[1]) is list :
					template , newSize, newElem = self.unfoldStruct(structElem[1])
					resultStruct.append(copy.deepcopy((structElem[0],template)))
					totelem += newElem
					size += newSize
				elif type(structElem[1]) is str :
					resultStruct.append(copy.deepcopy(structElem))
					size += len(structElem[1])/2
					totelem +=1
				elif type(structElem[1]) is int :
					resultStruct.append(copy.deepcopy(structElem))
					totelem += 1
					size += structElem[1]
				else:
					debug_msg("16",-1)
			else:
				debug_msg("16",-1)
		return resultStruct, size , totelem

	def getValFromBuffer(self,struct=[],name="",buffer=False,offset=0,fill="none",fillop="0",fillright=True,littleEdian=True,stringsAreConstants=False):
		nvalue, noffset, nelems, nresult = self.getVal(struct,name,fill,fillop,fillright)
		#print nvalue, noffset, nelems, nresult
		result = []
		for elem in nvalue:
			if elem[0] == "" \
			and stringsAreConstants == False:
				tmp, size = self.dataFromBuffer(self,elem[1],elem[2],littleEdian,fill,fillop,fillright)
			elif type(elem[0]) is tuple:
				tmp = self.callStructCustom(elem[1],("getValFromBuffer",struct,name,buffer,offset,fill,fillop,fillright,littleEdian,stringsAreConstants))
			else:
				tmp, retSize, retElem = self.resolvefillin(elem[2],elem[0],fillop,fillright)
			result.append(copy.deepcopy((tmp,elem[1],elem[2])))
		return result

	def getAllVal(self,struct=[],name="",fill="none",fillop="0",fillright=True):
		nvalue, noffset, nelems, nresult = self.getVal(struct,name,fill,fillop,fillright)
		return nvalue

	def getFirstVal(self,struct=[],name="",fill="none",fillop="0",fillright=True):
		nvalue, noffset, nelems, nresult = self.getVal(struct,name,fill,fillop,fillright)
		#print nvalue, noffset, nelems, nresult
		for elem in nvalue:
			return elem[0]
		return False

	def getLastVal(self,struct=[],name="",fill="none",fillop="0",fillright=True):
		nvalue, noffset, nelems, nresult = self.getVal(struct,name,fill,fillop,fillright)
		tmp = False
		for elem in nvalue:
			tmp = elem[0]
		return tmp

	def getVal(self,struct=[],name="",fill="none",fillop="0",fillright=True):
		if type(name) is not str:
			debug_msg("22",-1)
		result = []
		values = []
		offset = 0
		elems = 0
		for elem in struct:
			if type(elem[0]) is not str:
				debug_msg("16",-1)
			else:
				if elem[0] == name:
					if type(elem[1]) is int:
						tmp, retSize, retElem = self.resolvefillin(elem[1],fill,fillop,fillright)
						result.append(copy.deepcopy( (elem[0],tmp) ))
						values.append(copy.deepcopy(("",offset,tmp)))
						elems += 1
					elif type(elem[1]) is str:
						tmp, retSize, retElem = self.resolvefillin(elem[1],fill,fillop,fillright)
						result.append(copy.deepcopy( (elem[0],tmp) ))
						values.append(copy.deepcopy((tmp,offset,retSize)))
						elems += 1
					elif type(elem[1]) is list:
						tmp, retSize, retElem = self.resolvefillin(elem[1],fill,fillop,fillright)
						result.append(copy.deepcopy( (elem[0],tmp) ))
						values.append(copy.deepcopy(("",offset,tmp)))
						elems += 1
					elif type(elem[1]) is tuple:
						tmp, retElem, val = self.callStructCustom(elem[1],("getVal",name,fill,fillop,fillright))
						result.append(copy.deepcopy( (elem[0],tmp) ))
						values.append(copy.deepcopy((val,offset,tmp)))
						elems += retElem
					else:
						debug_msg("16",-1)
				else:
					if type(elem[1]) is list:
						nvalue, noffset, nelems, nresult = self.getVal(elem[1],name,fill,fillop,fillright)
						if nelems > 0:
							result.append(copy.deepcopy( (elem[0],nresult) ))
							for val in nvalue:
								values.append(val)
							elems += nelems
						offset += noffset
					elif type(elem[1]) is tuple:
						nvalue, noffset, nelems, nresult = self.callStructCustom(elem[1],("getVal",name,fill,fillop,fillright))
						if nelems > 0:
							for val in nvalue:
								values.append(val)
							elems += nelems
							result.append(copy.deepcopy( (elem[0],nresult) ))
						offset += noffset
					elif type(elem[1]) is int:
						offset += elem[1]
					elif type(elem[1]) is str:
						data = elem[1]
						if not self.testForHexOnly(data):
							data = binascii.b2a_hex(data)
						offset += len(data)/2
					else:
						debug_msg("16",-1)

		return values, offset, elems, result

	def dataFromBuffer(self,offset=0,size=0,littleEdian=True,fill="0",fillop="0",fillright=True,untill=False,addUntilBef=False,addUntilEnd=False,extraFromBuffer=False):
		currentOffset = 0
		data=""
		if untill != False:
			try:
				tmpBuff = self.buffer[offset:]
			except:
				tmpBuff = ""
			tmp = ""
			for elem in tmpBuff:
				if elem != untill:
					tmp += elem
					currentOffset += 1
				else:
					if addUntilBef:
						tmp += elem
						currentOffset += 1
					break
			data += self.byteStringToHexString_le(tmp,littleEdian)
			if addUntilEnd :
				data += untill
				currentOffset += 1
			size -= currentOffset
		if size > 0:
			length = 0
			tmpBuff = ""
			found = ""
			if untill == False or extraFromBuffer == True :
				try:
					tmpBuff = self.byteStringToHexString_le(self.buffer[offset:offset+size],littleEdian)
					length += len(tmpBuff)/2
					currentOffset += length
					size -= length
				except:
					debug_msg("15",-1)
			if size > 0:
				debug_msg("17",1)
				found, retSize, retElem = self.resolvefillin(size,fill,fillop,fillright)
				currentOffset += retSize
			if fillright:
				data += found + tmpBuff
			else:
				data += tmpBuff + found

		return data, currentOffset


	def structFromBuffer(self,struct=[],bufferoffset=0,fill="0",stringsAreConstants=False,fillop="0",fillright=True,littleEdian=True):
		resultStruct = []
		for structElem in struct:
			if type(structElem[0]) is not str:
				debug_msg("16",-1)
			elif type(structElem[1]) is str \
			and stringsAreConstants == True:
				found = structElem[1]
				bufferoffset += len(structElem[1])/2
			else:
				found = ""
				size = -1
				if type(structElem[1]) is int:
					size = structElem[1]
				elif type(structElem[1]) is str:
					size = len(structElem[1])/2
				if size > 0:
					found, noffset = self.dataFromBuffer(bufferoffset,size,littleEdian,fill,fillop,fillright)
					bufferoffset += noffset
				else:
					if type(structElem[1]) is tuple:
						found, offset = self.callStructCustom(structElem[1],("structFromBuffer",bufferoffset,fill,stringsAreConstants,fillop,fillright,littleEdian))
						bufferoffset += offset
					elif type(structElem[1]) is list:
						found , offset = self.structFromBuffer(structElem[1],bufferoffset,fill,stringsAreConstants,fillop,fillright,littleEdian)
						bufferoffset += offset
					else:
						debug_msg("16",-1)
			resultStruct.append(copy.deepcopy((structElem[0],found)))
		return resultStruct , bufferoffset

	def buildBufferString(self,struct=[],int_filling_option="0",str_filling_option="rnd",str_filling_to_right=True,littleEdian=True):
		returned_string = ""
		returned_size = 0
		returned_elmemnt_numbers = 0

		for elem in struct:
			if type(elem[0]) is not str:
				debug_msg("16",-1)
			else:
				if type(elem[1]) is int:
					temp_value, nretSize, nretElem = self.resolvefillin(elem[1],int_filling_option,str_filling_option,str_filling_to_right)
					temp_value, nretSize, nretElem = self.buildBufferString(temp_value,int_filling_option,str_filling_option,str_filling_to_right,littleEdian)
					returned_size += nretSize
					returned_elmemnt_numbers += nretElem
					returned_string +=  copy.deepcopy(temp_value)
				elif type(elem[1]) is str:
					temp_value = elem[1]
					if littleEdian:
						temp_value = self.swapLeBe(temp_value)
					returned_string +=  copy.deepcopy(temp_value)
					returned_size += len(temp_value)/2
					if (len(temp_value) % 2) == 1:
						returned_size += 1
					returned_elmemnt_numbers += 1
				elif type(elem[1]) is list:
					found, nretSize, nretElem = self.buildBufferString(elem[1],int_filling_option,str_filling_option,str_filling_to_right,littleEdian)
					returned_size += nretSize
					returned_elmemnt_numbers += nretElem
					returned_string +=  copy.deepcopy(found)
				elif type(elem[1]) is tuple:
					found, nretSize, nretElem = self.callStructCustom(elem[1],("dataToBuffer",int_filling_option,str_filling_option,str_filling_to_right,littleEdian))
					returned_size += nretSize
					returned_elmemnt_numbers += nretElem
					returned_string +=   copy.deepcopy(found)
				else:
					debug_msg("16",-1)
		return returned_string, returned_size, returned_elmemnt_numbers

	def fillbuffer(self,struct=[],offset=0,fill="0",fillop="rnd",fillright=True,overflow=True,innerflow=True,size=-1,push=True,littleEdian=True):
		resultString, retSize, retElem = self.buildBufferString(struct,fill,fillop,fillright,littleEdian)
		resultString = self.hexIt(resultString)
		if size != -1\
		and fill != "none":
			if retSize >= size:
				if overflow:
					if push:
						self.buffer = copy.deepcopy(self.buffer[:offset]+resultString+self.buffer[offset+size:])
					else:
						self.buffer = copy.deepcopy(self.buffer[:offset]+resultString+self.buffer[offset+nretSize:])
				else:
					self.buffer = copy.deepcopy(self.buffer[:offset]+resultString[:size]+self.buffer[offset+size:])
			else:
				if innerflow:
					if not push:
						#print(size-retSize)
						found, nretSize, nretElem = self.resolvefillin(size-retSize,fill,fillop,fillright)
						if littleEdian:
							found = self.swapLeBe(found)
						resultString += self.hexIt(copy.deepcopy(found))
						retSize += nretSize
						retElem += nretElem
					self.buffer = copy.deepcopy(self.buffer[:offset]+resultString+self.buffer[offset+size:])
				else:
					self.buffer = copy.deepcopy(self.buffer[:offset]+resultString+self.buffer[offset+retSize:])
		else:
			self.buffer = copy.deepcopy(self.buffer[:offset]+resultString+self.buffer[offset+retSize:])
		self.bufferSize = len(self.buffer)
		return retSize



	def mergeStructs(self,structA=[],structB=[],fill="none",fillop="0",fillright=True,ignoreNew=False,destructive=False):
		resultStruct = []
		notToAddList = []
		totalElem = 0 
		totalSize = 0  
		for structBE in structB:
			if type(structBE[0]) is not str:
				debug_msg("16",-1)
		for structAE in structA:
			if type(structAE[0]) is not str:
				debug_msg("16",-1)
			else:
				original = copy.deepcopy(structAE[1])
				found = original
				
				sizeA = -1
				if type(found) is int:
					sizeA = found
				toDelete = False
				for structBE in structB:
					if structBE[0] == structAE[0]:
						notToAddList.append(copy.deepcopy(structBE[0]))
						found = copy.deepcopy(structBE[1])
						toDelete = True
				save = False
				if destructive \
				and type(found) is not list:
					if not toDelete :
						save = True
				else:
					save = True
				if save :
					if type(found) is str \
					or type(found) is int:
						found, retSize, retElem = self.resolvefillin(found,fill,fillop,fillright,sizeA)
						totalSize += retSize
						totalElem += 1
					elif type(found) is list:
						found , newSize, newElem = self.mergeStructs(original,found,fill,fillop,fillright,ignoreNew,destructive)
						totalSize += newSize
						totalElem += newElem
					elif type(found) is tuple:
						found, newSize, newElem = self.callStructCustom(found,("mergingStruct",original,fill,fillop,fillright,ignoreNew,destructive))
						totalSize += newSize
						totalElem += newElem
					else:
						debug_msg("16",-1)
					resultStruct.append(copy.deepcopy((structAE[0],found)))
		if not ignoreNew:
			for structBE in structB:
				add = True
				for elems in notToAddList:
					if structBE[0] == elems:
						add = False
				if add:
					tmp, retSize, retElem = self.resolvefillin(structBE[1],fill,fillop,fillright,-1)
					resultStruct.append(copy.deepcopy((structBE[0],tmp)))
					totalSize += retSize
					totalElem += retElem
		return resultStruct, totalSize , totalElem

	def resolvefillin(self,the_data="",int_filling_option="0",str_filling_option="0",str_filling_to_right=True,str_mandatory_size=-1):
		
		returned_size = 0
		returned_elems = 1
		returned_data = ""
		if type(the_data) is str:
			if not self.testForHexOnly(the_data):
				the_data = binascii.b2a_hex(the_data)

			if len(the_data) % 2 == 1:
				if str_filling_to_right:
					the_data = "0" + the_data
				else:
					the_data = the_data + "0"

			data_byte_size = len(the_data)/2
			if the_data == "14c":
				print("here : %s" % (data_byte_size))
			if str_mandatory_size > -1:
				#since it's mandatory 
				returned_size = str_mandatory_size
				if data_byte_size >= str_mandatory_size:
					returned_data = the_data[:str_mandatory_size*2]
				else:
					data_missing_bytes = str_mandatory_size - data_byte_size
					if not str_filling_to_right:
						returned_data = the_data
					if str_filling_option == "0":
						for i in range(data_missing_bytes):
							returned_data += "00"
					elif str_filling_option == "rnd":
						returned_data += self.getRandomHex(data_missing_bytes*2)
					elif str_filling_option == "none":
						returned_size = data_byte_size
					else:
						debug_msg("20",-1)
					if str_filling_to_right:
						returned_data += the_data
			else:
				returned_size = data_byte_size
				returned_data = the_data
		elif type(the_data) is int:
			if int_filling_option == "none":
				returned_data = the_data
				returned_size += the_data
			else:
				returned_size += the_data
				if int_filling_option == "0":
					for i in range(the_data):
						returned_data += "00"
				elif int_filling_option == "rnd":
					returned_data = self.getRandomHex(the_data*2)
				elif type(int_filling_option) is str:
					returned_data , returned_size, returned_elems = self.resolvefillin(int_filling_option,"0",str_filling_option,str_filling_to_right,the_data)
				else:
					debug_msg("18",1)
		elif type(the_data) is list:
			resultData = []
			for elem in the_data:
				tmp , nretSize, nretElem = self.resolvefillin(elem[1],int_filling_option,str_filling_option,str_filling_to_right,-1)
				resultData.append(copy.deepcopy((elem[0],tmp)))
				returned_size += nretSize
				returned_elems += nretElem
			returned_data = resultData
		elif type(the_data) is tuple:
			returned_data, retSize, retElem = self.callStructCustom(data,("resolvingData",int_filling_option,str_filling_option,str_filling_to_right,str_mandatory_size))
			returned_size += nretSize
			returned_elems += nretElem
		else:
			debug_msg("18",-1)
		return returned_data , returned_size, returned_elems

	def writeBufferToFile(self,fileLoc,localBuffer=False):
		if localBuffer == False:
			localBuffer = self.buffer
		try:
			with open(fileLoc, "wb") as f:
				f.write(localBuffer)
			return True
		except:
			debug_msg("3",0)
			return False

	def fileToBuffer(self,fileLoc):
		result = ""
		try:
			file = open(fileLoc, "rb")
			result = file.read()
			file.close()
		except :
			debug_msg("1",-1)
		self.buffer += result
		self.bufferSize += len(self.buffer)
		return self.bufferSize

	def validOptions(self):
		op = self.options
		if type(op["type"]) is not str \
		or type(op["location"]) is not str :
			debug_msg("2",-1)

	def callStructCustom(self,options,struct_offset):
		try:
			return self.options["customFunctions"][options[0]](self,options[1:],struct_offset)
		except:
			debug_msg("9",-1)
