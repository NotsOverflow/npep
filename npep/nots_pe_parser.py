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



def round_it(n, r):
  return "%X" % ((n+(r-1))/r)*r


def hello(filea):
  bb = nbt.BinaryBuffer({"littleEdian":False})
  #bb.fileToBuffer(filea)

  code_pack = [
    ("mov eax 42" , "b82a000000"), 
    ("ret", "c3") 
  ]
  code , code_size, code_elem = bb.unfoldStruct(code_pack)

  print(" Code size : %s" % (code_size))

  #what i need to know first place

  size_of_dos_code = 0
  filealign = 1
  sectalign = 1

  #getting some info

  mzhdr , mzhdr_size, mzhdr_elem = bb.unfoldStruct(ps.pe_struct._IMAGE_DOS_HEADER)
  hdr, hdr_size, hdr_elem = bb.unfoldStruct(ps.pe_struct._IMAGE_NT_HEADERS_32)
  optional_hdr = bb.getAllVal(hdr,"_Image_Optional_HEADER")
  optional_hdr = optional_hdr[0][2]
  optional_hdr, optional_hdr_size, optional_hdr_elem = bb.unfoldStruct(optional_hdr)
  text, text_size, text_elem = bb.unfoldStruct(ps.pe_struct._IMAGE_SECTION_HEADER)

  print(" Sizes : mzhdr %s / hdr %s / ophdr %s / text %s" % (mzhdr_size, hdr_size, optional_hdr_size, text_size))

  # what i know now

  hdr_offset = mzhdr_size + size_of_dos_code
  total_header_size = hdr_offset + hdr_size + text_size
  code_entryPoint = total_header_size + (filealign/2)
  filesize = code_entryPoint + code_size

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
      ("NumberOfSections", "1"),
      ("TimeDateStamp", "4545be5d"),
      ("SizeOfOptionalHeader", "%X" % optional_hdr_size),
      ("Characteristics", "103")
    ]),
    ("_Image_Optional_HEADER" , [ 
      ("Magic" , "10b" ),
      ( "MajorLinkerVersion", "8"),
      ( "SizeOfCode", "%X" % code_size),
      ("AdressOfEntryPoint" , "%X" % code_entryPoint ),
      ( "BaseOfCode", "%X" %  code_entryPoint),
      ("BaseOfData" , "%X" % filesize ),
      ("ImageBase" , "400000" ), 
      ("SectionAlignment", str(sectalign) ), 
      ("FileAlignement", str(filealign) ),
      ("MajorOperatingSystemVersion", "4" ), 
      ("MajorSubsystemVersion", "4" ),
      ("DllCharacteristics", "400" ),
      ("SizeOfStackReserve", "100000" ),
      ("SizeOfStackCommit", "1000" ),
      ("SizeOfHeapReserve", "100000" ),
      ("SizeOfHeapCommit" , "1000" ),
      ("SizeOfImage", round_it(filesize, sectalign) ),
      ("SizeOfHEaders", round_it(total_header_size, filealign) ),
      ("Subsystem", "2" ),
      ("NumberOfRvaAnSizes", "10")
    ])
  ]
  text_pack = [
    ("Name" , ".text\x00\x00\x00"[::-1]),
    ("VirtualSize" , "%X" %  code_size),
    ("VirtualAdress" , round_it(total_header_size, sectalign)),
    ("SizeOfRawData" , round_it(code_size, filealign)),
    ("PointerToRawData" , "%X" % code_entryPoint),
    ("Characteristics" , "60000020"),
    ("_FileAlignement",filealign / 2)
  ]

  # let's build the actual data

  mzhdr_paked, mzhdr_paked_size , mzhdr_paked_elem = bb.mergeStructs(mzhdr,mzhdr_pack,"0")
  hdr_paked, hdr_paked_size , hdr_paked_elem = bb.mergeStructs(hdr,hdr_pack,"0")
  text_paked, text_paked_size , text_paked_elem = bb.mergeStructs(text,text_pack,"0")

  peFile = [
    ("mzhdr", mzhdr_paked),
    ("hdr", hdr_paked),
    ("text", text_paked),
    ("code", code)
  ]

  

  bb.buffer = ""
  bb.buffer_size = 0
  bb.fillbuffer(peFile)
  #bb.fileToBuffer("shellcode")
  #bb.buffer = bb.buffer + code
  bb.writeBufferToFile(filea)
  print(" Used structurs ")

  #pp.pprint(peFile)

  