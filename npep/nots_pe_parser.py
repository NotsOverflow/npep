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

import nbt
import pestructs as ps
import pprint
pp = pprint.PrettyPrinter(indent=2)
import binascii





def round_it_int(n, r):
  result = n % r
  result = r - ( r if result == 0 else result )
  result = n + round_it_gap(n,r)
  return result

def round_it_gap(n,r):
  result = n % r
  result = r - ( r if result == 0 else result )
  return result

def round_it(n, r):
  return "%X" % round_it_int(n, r)

def hello(filea):
  bb = nbt.BinaryBuffer()
  #bb.fileToBuffer(filea)

  swap_le = bb.swapLeBe


  #dos code part

  dos_code_pack = [
    ("empty",0)
  ]
  dos_code , dos_code_size, dos_code_elem = bb.unfoldStruct(dos_code_pack)

  print(" Dos code size : %s" % (dos_code_size))

  #windows code

  code_pack = [
    ("mov eax 42" , swap_le("b82a000000")), 
    ("ret", "c3") 
  ]
  code_pack2 = [
    ("push 42",swap_le("6a2a")),
    ("pop eax", "58"),
    ("ret","C3")
  ]
  code_exit = [
    ("xor eax, eax", swap_le("31d2")),
    ("mov eax, $0x75c73aca", "75c73acaa1"),
    ("call eax", swap_le("ffd0"))
  ]
  sleep_500 = [
    ("xor eax, eax", swap_le("31c0")),
    ("mov ebx, $0x75c759a8", swap_le("8b1da859c775")),
    ("mov ax, $0x1388", swap_le("66b88813")),
    ("push eax", "50"),
    ("call ebx", swap_le("ffd3"))
  ]
  sleep_and_exit = [
    ("sleep", sleep_500),
    ("exit", code_exit)
  ]
  code , code_size, code_elem = bb.unfoldStruct(sleep_and_exit)


  print(" Code size : %s" % (code_size))


  # data section code

  data = [
    ("empty",0)
  ]
  data , data_size, data_elem = bb.unfoldStruct(data)

  print(" Data size : %s" % (data_size))

  #what i need to know first place

  sectalign = 4096
  filealign = 512

  #getting some info
  mzhdr , mzhdr_size, mzhdr_elem = bb.unfoldStruct(ps.pe_struct._IMAGE_DOS_HEADER)
  hdr, hdr_size, hdr_elem = bb.unfoldStruct(ps.pe_struct._IMAGE_NT_HEADERS_32)
  optional_hdr = bb.getAllVal(hdr,"_Image_Optional_HEADER")
  optional_hdr = optional_hdr[0][2]
  optional_hdr, optional_hdr_size, optional_hdr_elem = bb.unfoldStruct(optional_hdr)
  text_section, text_section_size, text_section_elem = bb.unfoldStruct(ps.pe_struct._IMAGE_SECTION_HEADER)
  data_section, data_section_size, data_section_elem = bb.unfoldStruct(ps.pe_struct._IMAGE_SECTION_HEADER)

  print(" Sizes : mzhdr %s / hdr %s / ophdr %s / text %s / data %s" % (mzhdr_size, hdr_size, optional_hdr_size, text_section_size, data_section_size))

  # what i know now
  filealign = (filealign/2)*2
  sectalign = (sectalign/2)*2
  
  hdr_offset = mzhdr_size + dos_code_size
  hdr_mzhdr_gap = round_it_gap(hdr_offset, filealign)
  hdr_offset += hdr_mzhdr_gap
  total_header_size = hdr_offset + hdr_size + text_section_size + data_section_size
  code_header_gap = round_it_gap(total_header_size,filealign)
  code_entryPoint = total_header_size + code_header_gap
  data_code_gap = round_it_gap(code_size,filealign)
  data_entryPoint = code_entryPoint + code_size + data_code_gap
  filesize = data_entryPoint + data_size
  end_data_gap = round_it_gap(data_size, filealign)


  print(" Sizes : hdr_offset %s / total_header_size %s / code_entryPoint %s / filesize %s" % (hdr_offset, total_header_size, code_entryPoint, filesize))

  # let's build  packs

  mzhdr_pack = [
    ("e_magic" , "MZ"[::-1]), # signature
    ("e_lfanew", "%X" % hdr_offset) # Offset to new EXE Header
  ]

  hdr_pack = [
    ("Signature" , "PE"[::-1]),
    ("_IMAGE_FILE_HEADER" , [ 
      ("Machine", "14c"),
      ("NumberOfSections", "2"),
      ("TimeDateStamp", "4545be5d"),
      ("SizeOfOptionalHeader", "%X" % optional_hdr_size),
      ("Characteristics", "10f")
    ]),
    ("_Image_Optional_HEADER" , [ 
      ("Magic" , "10b" ),
      ("MajorLinkerVersion", "0a"),
      ("MinorLinkerVersion" , "0" ),
      ("SizeOfCode", "%X" % code_size),
      ("SizeOfInitializedData" , "%X" % data_size ) ,
      ("AdressOfEntryPoint" , "%X" % code_entryPoint ),
      ("BaseOfCode", "%X" %  code_entryPoint),
      ("BaseOfData" , "%X" % data_entryPoint ),
      ("ImageBase" , "400000" ), 
      ("SectionAlignment", "%X" % sectalign ), 
      ("FileAlignement", "%X" % filealign ),
      ("SizeOfImage", round_it(filesize, sectalign) ),
      ("SizeOfHEaders", round_it(total_header_size, filealign) ),
      ("Subsystem", "2" ),
      ("SizeOfStackReserve", "100000" ),
      ("SizeOfStackCommit", "4000" ),
      ("SizeOfHeapReserve", "100000" ),
      ("SizeOfHeapCommit" , "1000" ),
      ("NumberOfRvaAnSizes", "10"),
      ("MajorOperatingSystemVersion", "6" ), 
      ("MajorSubsystemVersion", "6" ),
      ("DllCharacteristics", "400" ),
      ("_IMAGE_DATA_DIRECTORY_ENTRY_IMPORT", [
        ("VirtualAdress" , "2000"),
        ("Size" , "30")
      ])
    ])
  ]
  sectalign_offset = round_it_int(total_header_size, sectalign)
  text_section_pack = [
    ("Name" , ".text\x00\x00\x00"[::-1]),
    ("VirtualSize" , "%X" %  code_size),
    ("VirtualAdress" , "%X" % sectalign_offset),
    ("SizeOfRawData" , round_it(code_size, filealign)),
    ("PointerToRawData" , "%X" % code_entryPoint),
    ("Characteristics" , "60000060")
  ]
  sectalign_offset += round_it_int(code_size, sectalign)
  data_section_pack = [
    ("Name" , ".data\x00\x00\x00"[::-1]),
    ("VirtualSize" , "%X" %  data_size),
    ("VirtualAdress" , "%X" % sectalign_offset),
    ("SizeOfRawData" , "%X" % ( data_size + end_data_gap )),
    ("PointerToRawData" , "%X" % data_entryPoint),
    ("Characteristics" , "c00000c0")
  ]
  # let's build the actual data

  mzhdr_paked, mzhdr_paked_size , mzhdr_paked_elem = bb.mergeStructs(mzhdr,mzhdr_pack,"0")
  hdr_paked, hdr_paked_size , hdr_paked_elem = bb.mergeStructs(hdr,hdr_pack,"0")
  text_section_paked, text_section_paked_size , text_section_paked_elem = bb.mergeStructs(text_section,text_section_pack,"0")
  data_section_paked, data_section_paked_size , data_section_paked_elem = bb.mergeStructs(data_section,data_section_pack,"0")

  peFile = [
    ("mzhdr", mzhdr_paked),
    ("_align",hdr_mzhdr_gap),
    ("hdr", hdr_paked),
    ("text_section", text_section_paked),
    ("data_section", data_section_paked),
    ("_align",code_header_gap),
    ("code", code),
    ("_align",data_code_gap),
    ("data", data),
    ("_align",end_data_gap)
  ]

  #pp.pprint(peFile);quit()

  

  
  bb.fillbuffer(peFile)
  #bb.fileToBuffer("shellcode")
  #bb.buffer = bb.buffer + code
  bb.writeBufferToFile(filea)
  print(" Used structurs ")

  #pp.pprint(peFile)

  