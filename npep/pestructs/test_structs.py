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
from collections import OrderedDict

_somedata = [
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
_firstdata = [
	("e_magic","5a4d"),
	("e_lfanew", "00000040")
]

_TEST_STRUCTSMALL = [
	("e_magic" , 2), # signature
	("e_cblp" , 2), # bytes on last page of file
	("e_cp" , 2),
	("_IMAGE_FILE_HEADER",[
		("machine",4),
		("test",2),
		(
			[
				("nested",2),
				("_name",[
					("subnested", 4),
					("subnested2", 2)
				])
			],
			[
				"test1",
				"test2",
				"test3"
			]
		)
	]),
	("e_lfanew", 4)
]

_TEST_STRUCT = [
	("e_magic" , 4), # signature
	("e_cblp" , 2), # bytes on last page of file
	("e_cp" , 2), #Pages in File
	("e_crlc" , 2),
	("_IMAGE_FILE_HEADER" , [ # FileHeader
		("Machine" , 2),
		("NumberOfSections" , 2),
		("TimeDateStamp" , 4),
		("PointerToSymbolTable" , 4),
		("NumberOfSymbols" , 4),
		("SizeOfOptionalHeader" , 2),
		("Characteristics" , 2),
		(
			[ 
				("VirtualAdress" , 4),
				("Size" , 4)
			],
			[
				"_IMAGE_DATA_DIRECTORY_ENTRY_EXPORT" , 
				"_IMAGE_DATA_DIRECTORY_ENTRY_IMPORT",
				"_IMAGE_DATA_DIRECTORY_ENTRY_RESOURCE"
			]
		),
		("Characteristics" , 2)
	]),
	("e_crlv" , 2)
]

_IMAGE_DOS_HEADER = [
	("e_magic" , 2), # signature
	("e_cblp" , 2), # bytes on last page of file
	("e_cp" , 2),#Pages in File
	("e_crlc" , 2), #Relocations
	("e_cparhdr", 2), #Size of header in paragraphs
	("e_minalloc", 2), # minimum extra paragraphs
	("e_maxalloc", 2), # maxalloc
	("e_ss", 2 ),# initial ( relative ) ss
	("e_sp", 2 ),# initial sp
	("e_csum", 2), # checksum
	("e_iip", 2), # initial ip
	("e_ics", 2), # overlay number
	("e_otrt", 2), # Reserved
	("e_ovnb", 2), # Reserved
	("e_res0", 2), # Reserved
	("e_res1", 2), # Reserved
	("e_res2", 2), # Reserved
	("e_res3", 2), # Reserved
	("e_oemid", 2), # OEM id
	("e_oeminfo", 2), # OEM info
	("e_res4", 2), # Reserved
	("e_res5", 2), # Reserved
	("e_res6", 2), # Reserved
	("e_res7", 2), # Reserved
	("e_res8", 2), # Reserved
	("e_res9", 2), # Reserved
	("e_resa", 2), # Reserved
	("e_resb", 2), # Reserved
	("e_resc", 2), # Reserved
	("e_resd", 2), # Reserved
	("e_lfanew", 4) # Offset to new EXE Header
]

_IMAGE_NT_HEADERS_32 = [
	("Signature" , 4), # pe magic
	("_IMAGE_FILE_HEADER" , [ # FileHeader
		("Machine" , 2),
		("NumberOfSections" , 2),
		("TimeDateStamp" , 4),
		("PointerToSymbolTable" , 4),
		("NumberOfSymbols" , 4),
		("SizeOfOptionalHeader" , 2),
		("Characteristics" , 2)
	]),
	("_Image_Optional_HEADER" , [ #OptionalHeade 
		("Magic" , 2 ),
		("MajorLinkerVersion" , 1 ),
		("MinorLinkerVersion" , 1 ),
		("SizeOfCode" , 4 ),
		("SizeOfInitializedData" , 4 ) ,
		("SizeOfUninitializedData" , 4  ),
		("AdressOfEntryPoint" , 4 ), 
		("BaseOfCode" , 4 ), 
		("BaseOfData" , 4 ), 
		("ImageBase" , 4 ), 
		("SectionAlignment", 4 ), 
		("FileAlignement", 4 ),
		("MajorOperatingSystemVarsion", 2 ), 
		("MinorOperatingSystemVersion", 2 ),
		("MajorImageVersion", 2 ),
		("MinorImageVersion", 2 ),
		("MajorSubsystemVersion", 2 ),
		("MinorSubsystemVersion", 2 ),
		("Win32VersionValue", 4 ),
		("SizeOfImage", 4 ),
		("SizeOfHEaders", 4 ),
		("CheckSum", 4 ),
		("Subsystem", 2 ),
		("DllCharacteristics", 2 ),
		("SizeOfStackReserve", 4 ),
		("SizeOfStackCommit", 4 ),
		("SizeOfHeapReserve", 4 ),
		("SizeOfHeapCommit" , 4 ),
		("LoaderFlags", 4 ),
		("NumberOfRvaAnSizes", 4),
		([
			("VirtualAdress", 4),
			("Size", 4)
		],[
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

_IMAGE_NT_HEADERS_32p = [
	("Signature" , 4), # pe magic
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

_IMAGE_EXPORT_DIRECTORY = {
	"Characteristics" : 4,
	"TimeDateStamp" : 4,
	"MajorVersion" : 2,
	"MinorVersion" : 2,
	"Name" : 4,
	"Base" : 4,
	"NumberOfFunctions" : 4,
	"NumberOfNames" : 4,
	"AdressOfFunctions" : 4,
	"AdressOfNames" : 4,
	"AdressOfNAmeOrdinals" : 4
}

_IMAGE_IMPORT_DESCRIPTOR = [
	("Characteristics" , 4 ), # Can point to originalFirstThunk
	("TimeDateStamp" , 4),
	("ForwarderChain" , 4),
	("Name" , 4), # if bound to IAT has actual adresses
	("FirstThunk" , 4)
]

_IMAGE_RESOURCE_DIRECTORY = {
	"Characteristics" : 4,
	"TimeDateStamp" : 4,
	"MajorVersion" : 2,
	"MinorVersion" : 2,
	"NumberOfNamedEntries" : 2,
	"NumberOfIdEntries" : 2
}

_IMAGE_RESOURCE_DIRECTORY_ENTRIES = {
	"DataRVA" : 4,
	"Size" : 4,
	"CodePage" : 4,
	"Reserved" : 4
}

_IMAGE_RESOURCE_DIRECTORY_STRING = {
	"Length" : 4,
	"UString" : ("peLine",4)
}

_IMAGE_RESOURCE_DATA_ENTRIES = {
	"NameRVA" : 4,
	"IntegerID" : 4,
	"DataEntryRVA" : 4,
	"SubdirectoryRVA" : 4
}

_IMAGE_TLS_DIRECTORY_32 = {
	"StartAdressOfRawData" : 4,
	"EndAdressOfRawData" : 4,
	"AdressOfIndex" : 4,
	"AdressOfCallBacks" : 4,
	"SizeOfZeroFill" : 4,
	"Characteristics" : 4
}

_IMAGE_TLS_DIRECTORY_32p = {
	"StartAdressOfRawData" : 8,
	"EndAdressOfRawData" : 8,
	"AdressOfIndex" : 8,
	"AdressOfCallBacks" : 8,
	"SizeOfZeroFill" : 4,
	"Characteristics" : 4
}

_IMAGE_DELAY_IMPORT_DESCRIPTOR = {
	"grAttrs" : 4,
	"szName" : 4,
	"phmod" : 4,
	"pIAT" : 4,
	"pINT" : 4,
	"pBoundIAT" : 4,
	"pUnloadIAT" : 4,
	"dwTimeStamp" : 4
}

_IMAGE_SECTION_HEADER = {
	"Name" : 8,
	"VirtualSize" : 4,
	"VirtualAdress" : 4,
	"SizeOfRawData" : 4,
	"PointerToRawData" : 4,
	"PointerToReloacations" : 4,
	"PointerToLineNumbers" : 4,
	"NumberOfReloacations" : 2,
	"NumberOfLinenumbers" : 2,
	"Characteristics" : 4
}

_IMAGE_LOAD_CONFIGURATION_LAYOUT_32 = {
	"Characteristics" : 4,
	"TimeDateStamp" : 4,
	"MajorVersion" : 2,
	"MinorVersion" : 2,
	"GlobalFlagsClear" : 4,
	"GlobalFlagSet" : 4,
	"CriticalSectionDefaultTimeout" : 4,
	"DeCommitFreeBlockThreshold" : 8,
	"DeCommitTotalFreeThreshold" : 8,
	"LockPrefixTable" : 8,
	"MaximumAllocationSize" : 8,
	"VirtualMemoryThreshold" : 8,
	"ProcessAffinityMask" : 8,
	"ProcessHeapFlags" : 4,
	"CSDVersion" : 2,
	"Reserved" : 2,
	"EditList" : 8,
	"SecurityCookie" : 4,
	"SEHandlerTable" : 4,
	"SEHandlerCount" : 4
}
_IMAGE_LOAD_CONFIGURATION_LAYOUT_32p = {
	"Characteristics" : 4,
	"TimeDateStamp" : 4,
	"MajorVersion" : 2,
	"MinorVersion" : 2,
	"GlobalFlagsClear" : 4,
	"GlobalFlagSet" : 4,
	"CriticalSectionDefaultTimeout" : 4,
	"DeCommitFreeBlockThreshold" : 8,
	"DeCommitTotalFreeThreshold" : 8,
	"LockPrefixTable" : 8,
	"MaximumAllocationSize" : 8,
	"VirtualMemoryThreshold" : 8,
	"ProcessAffinityMask" : 8,
	"ProcessHeapFlags" : 4,
	"CSDVersion" : 2,
	"Reserved" : 2,
	"EditList" : 8,
	"SecurityCookie" : 8,
	"SEHandlerTable" : 8,
	"SEHandlerCount" : 8
}


