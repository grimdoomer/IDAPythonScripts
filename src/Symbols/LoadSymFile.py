"""
	LoadSymFile.py - IDA python script to load a Psy-Q .sym file into the current database.
	
	Grimdoomer
"""

import idaapi
import idautils
import idc
import struct
import os

def main():

	# Refer to https://github.com/sanctuary/sym for symbol file format.

	symbolCount = 0
	
	# Prompt the user for the sym file.
	fileName = AskFile(0, "*.sym", "Psy-Q Sym File")
	
	# Open the sym file for reading.
	with open(fileName, mode='rb') as file:
	
		# Get the size of the file.
		file.seek(0, os.SEEK_END)
		fileSize = file.tell()
		file.seek(0)
	
		# Check the header magic.
		magicval = struct.unpack('I', file.read(4))[0]
		print("= %s" % str(magicval))
		if magicval != 0x01444E4D:
		
			# Invalid magic value.
			print("Sym file \"%s\" is invalid!" % fileName)
			return
			
		# Skip next 4 bytes.
		file.read(4)
		
		# Loop until we have read the entire file.
		while file.tell() != fileSize:
		
			# Read symbol address and type.
			symbolAddress = struct.unpack('I', file.read(4))[0]
			symbolType = struct.unpack('B', file.read(1))[0]
			print("Type=%x Offset=%d" % (symbolType, file.tell()))
			
			# Check the symbol type and handle accordingly.
			if symbolType == 1 or symbolType == 2 or symbolType == 5 or symbolType == 6:
			
				# Symbol name.
				nameLength = struct.unpack('B', file.read(1))[0]
				symbolName = file.read(nameLength).decode('utf-8')
				
				# Create the symbol name.
				idaapi.set_name(symbolAddress, str(symbolName), idaapi.SN_PUBLIC)
				symbolCount += 1
				
			elif symbolType == 0x80:
			
				# Increment current line number, NOP.
				pass
				
			elif symbolType == 0x82:
			
				# Increment current line number by byte, NOP.
				lineSkip = struct.unpack('B', file.read(1))[0]
				
			elif symbolType == 0x84:
			
				# Increment current line number by word, NOP.
				lineSkip = struct.unpack('I', file.read(2))[0]
				
			elif symbolType == 0x86:
			
				# Set current line number, NOP.
				lineNumber = struct.unpack('I', file.read(4))[0]
				
			elif symbolType == 0x88:
			
				# Set current line number and source file, NOP.
				lineNumber = struct.unpack('I', file.read(4))[0]
				fileNameLength = struct.unpack('B', file.read(1))[0]
				sourceFileName = file.read(fileNameLength).decode('utf-8')
				
			elif symbolType == 0x8A:
			
				# End of line specifier, NOP.
				pass
				
			elif symbolType == 0x8C:
			
				# Function start.
				framePointer = struct.unpack('H', file.read(2))[0]
				functionSize = struct.unpack('I', file.read(4))[0]
				returnRegister = struct.unpack('H', file.read(2))[0]
				mask = struct.unpack('I', file.read(4))[0]
				maskOffset = struct.unpack('I', file.read(4))[0]
				lineNumber = struct.unpack('I', file.read(4))[0]
				fileNameLength = struct.unpack('B', file.read(1))[0]
				sourceFileName = file.read(fileNameLength).decode('utf-8')
				symbolNameLength = struct.unpack('B', file.read(1))[0]
				symbolName = file.read(symbolNameLength).decode('utf-8')
				
				# Make this code block a function.
				idc.MakeFunction(symbolAddress)
				
				# Put a comment in the function with extended info.
				idc.MakeFunctionCmt(symbolAddress, str("FP: %d\nFunction Size: 0x%x\nReturn Register: r%d\nMask: 0x%08x\nMask Offset: %d\nSource File Name: %s\n Line Number: %d" % 
					(framePointer, functionSize, returnRegister, mask, maskOffset, sourceFileName, lineNumber)))
				
				# Create the symbol name.
				idaapi.set_name(symbolAddress, str(symbolName), idaapi.SN_PUBLIC)
				symbolCount += 1
				
			elif symbolType == 0x8E:
			
				# Function end, NOP.
				lineNumber = struct.unpack('I', file.read(4))[0]
				
			elif symbolType == 0x90:
			
				# Block start, NOP.
				lineNumber = struct.unpack('I', file.read(4))[0]
				
			elif symbolType == 0x92:
			
				# Block end, NOP.
				lineNumber = struct.unpack('I', file.read(4))[0]
				
			elif symbolType == 0x94:
			
				# Def symbol type 1.
				defClass = struct.unpack('H', file.read(2))[0]		# See https://github.com/sanctuary/sym/blob/master/class.go
				defType = struct.unpack('H', file.read(2))[0]		# See https://github.com/sanctuary/sym/blob/master/type.go
				defSize = struct.unpack('I', file.read(4))[0]
				defNameLength = struct.unpack('B', file.read(1))[0]
				defName = file.read(defNameLength).decode('utf-8')
				
				# Just leave a comment at the address for now.
				idc.MakeComm(symbolAddress, str("Class=%d Type=%d Size=%d" % (defClass, defType, defSize)))
				symbolCount += 1
				
			elif symbolType == 0x96:
			
				# Def symbol type 2.
				defClass = struct.unpack('H', file.read(2))[0]		# See https://github.com/sanctuary/sym/blob/master/class.go
				defType = struct.unpack('H', file.read(2))[0]		# See https://github.com/sanctuary/sym/blob/master/type.go
				defSize = struct.unpack('I', file.read(4))[0]
				dimsLength = struct.unpack('H', file.read(2))[0]
				dimensions = []
				for i in range(dimsLength):
					dimensions.append(struct.unpack('I', file.read(4))[0])
					
				tagLength = struct.unpack('B', file.read(1))[0]
				tag = file.read(tagLength).decode('utf-8')
				defNameLength = struct.unpack('B', file.read(1))[0]
				defName = file.read(defNameLength).decode('utf-8')
				
				# Just leave a comment at the address for now.
				idc.MakeComm(symbolAddress, str("Class=%d Type=%d Size=%d Dims=%d Tag=%s" % (defClass, defType, defSize, dimsLength, tag)))
				symbolCount += 1
				
			elif symbolType == 0x98:
			
				# File overlay.
				overlaySize = struct.unpack('I', file.read(4))[0]
				overlayID = struct.unpack('I', file.read(4))[0]
				
				# Leave a comment with the overlay information.
				idc.MakeComm(symbolAddress, str("Overlay Size=%d ID=%d" % (overlaySize, overlayID)))
				
			elif symbolType == 0x9A:
			
				# Set active overlay, NOP.
				pass
				
			elif symbolType == 0x9C:
			
				# Not sure what this one is...
				file.read(28)
				fileNameLength = struct.unpack('B', file.read(1))[0]
				sourceFileName = file.read(fileNameLength).decode('utf-8')
				functionNameLength = struct.unpack('B', file.read(1))[0]
				functionName = file.read(functionNameLength).decode('utf-8')
				
			else:
			
				# Unsupported symbol type.
				print("Symbol type 0x%02x at offset %d is unsupported, aborting!" % (symbolType, file.tell()))
				return
			
	# Print the results.
	print("Labeled %d symbols!" % symbolCount)
	
main()