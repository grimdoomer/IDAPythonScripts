"""

"""

from idaapi import *
from idautils import *
from collections import namedtuple

# Create various Tuples to help us store data.
AddressableString = namedtuple('AddressableString', 'str, ea')

def buildLTCStringList():
    # Initialize our string list.
    stringList = []

    # Initialize the strings from ida.
    strings = Strings()

    # Loop through all of the strings in the module.
    for s in enumerate(strings):
        # Check if the string is null.
        if (s is None):
            pass

        # Check if the string contains the substring 'libtomcrypt'.
        if (str(s[1]).lower().find("libtomcrypt") != -1):
            # Add the string to the list.
            stringList.append(AddressableString(str(s[1]), s[1].ea))


    # Return the string list.
    return stringList


def findStringInList(stringList, subString):
    # Loop through all the strings in the list.
    for i in range(0, len(stringList)):
        # Check if the current string contains the substring.
        print stringList[i].str
        index = stringList[i].str.find(subString)
        if (index != -1):
            return i

    # No string containing the substring was found in the list.
    return -1


def labelFunction(stringList, keyword, funcName):
    # Search the string list for our keyword.
    index = findStringInList(stringList, keyword)
    #print "str_addr=0x%08x" % stringList[index].ea
    if (index != -1):
        # Get the first xref to this string.
        xrefList = XrefsTo(stringList[index].ea, 0)
        if (xrefList != None):
            # Navigate to the first xref and that will be the function we need to label.
            for xref in xrefList:
                #print "xref=0x%08x" % xref.frm

                # We need to create the function just in case it doesn't already exist.

                # Now get the function address which should be good.
                funcAddr = get_func(xref.frm).startEA

                # Label the function.
                if (funcAddr != idaapi.BADADDR):
                    #set_name(funcAddr, funcName)
                    print "addr=0x%08x" % funcAddr
                else:
                    print "Unable to find function for xref to %s, skipping function..." % keyword

                # Break the loop, we only wanted the first entry.
                break
        else:
            print "No xrefs to %s string found, skipping function..." % keyword


def labelRSAFunctions(stringList):
    # rsa_import.c
    #labelFunction(stringList, "rsa_import.c", "LTC_rsa_import")

    # rsa_verify_hash.c
    labelFunction(stringList, "rsa_verify_hash.c", "LTC_verify_hash")


def main():
    # Build the list of libtomcrypt strings.
    stringList = buildLTCStringList()
    if (len(stringList) == 0):
        # No LTC strings found in the module.
        print "No LibTomCrypt strings found in the module!"
        return

    # Label the rsa functions.
    labelRSAFunctions(stringList)

    # Tell the user we are done.
    print "Done."


main()
