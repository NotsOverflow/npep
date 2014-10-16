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

import npep, sys

def exit_the_prog():
	usage = "\n\tUsage:\n\t\t%s <Windows PE file> " % (sys.argv[0])
	print(usage)
	quit()

if __name__ == "__main__":

	if len(sys.argv) != 2:
		exit_the_prog()
	npep.hello(sys.argv[1])