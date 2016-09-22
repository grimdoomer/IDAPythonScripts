"""

"""

from idaapi import *
from idc import *

def idaCharArrayToSafeString(array):
    # Initialize our clean string array.
    safeStr = ""

    # Loop through the entire IDA string until we reach a 0x00 value.
    for i in range(len(array)):
        # Check if the character is valid.
        if (ord(array[i]) != 0):
            safeStr = safeStr + array[i]
        else:
            return str(safeStr)


def findFunctionStartPowerPC(ea, maxDistance):
    # Search upward for the "mflr %r12" instruction.
    addr = FindText(ea, SEARCH_UP, 0, 0, "mflr      r12")
    #print "Find: addr=0x%08x" % addr
    return addr


def findFunctionStart(ea, maxDistance):
    # Check the processor type and handle accordingly.
    info = get_inf_structure()
    processor = idaCharArrayToSafeString(info.procName)
    if (processor == "PPC"):
        return findFunctionStartPowerPC(ea, maxDistance)
    else:
        # The current processor type is not supported!
        print "SearchUtilities::findFunctionStart(): Processor type %s is not supported!" % processor
        return BADADDR
