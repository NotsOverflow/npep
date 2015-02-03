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
		("MajorOperatingSystemVersion", 2 ), 
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

_IMAGE_SECTION_HEADER = [
	("Name" , 8),
	("VirtualSize" , 4),
	("VirtualAdress" , 4),
	("SizeOfRawData" , 4),
	("PointerToRawData" , 4),
	("PointerToReloacations" , 4),
	("PointerToLineNumbers" , 4),
	("NumberOfReloacations" , 2),
	("NumberOfLinenumbers" , 2),
	("Characteristics" , 4)
]