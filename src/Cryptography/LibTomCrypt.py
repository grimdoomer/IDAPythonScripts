"""
    Author: Ryan Miceli

    Created: 9/20/16

    LibTomCrypt.py:
        Python script for IDA to help label functions from the LibTomCrypt cryptography library.

"""

from idaapi import *
from idautils import *
from collections import namedtuple
from Utilties import SearchUtilities
from idc import *

# Create various Tuples to help us store data.
AddressableString = namedtuple('AddressableString', 'str, ea')

# Get the list of strings from IDA.
g_StringList = Strings()

def findString(string, matchExact):
    # Enumerate through the string list and search for our string.
    for s in enumerate(g_StringList):
        # Check if the string is null.
        if (s is None):
            pass

        # Check if the current string matches our search criteria.
        if (matchExact == False and str(s[1]).lower().find(string) != -1):
            return AddressableString(str(s[1]), s[1].ea)
        elif (matchExact == True and str(s[1]) == string):
            return AddressableString(str(s[1]), s[1].ea)

    # The string was not found.
    return None


def buildLTCStringList():
    # Initialize our string list.
    stringList = []

    # Loop through all of the strings in the module.
    for s in enumerate(g_StringList):
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
        #print stringList[i].str
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

                # Find the start of this function in case the function does already exist.
                startAddr = SearchUtilities.findFunctionStart(xref.frm, 10)  # Only search 10 instructions back.
                if (startAddr != BADADDR):
                    # Check if there is an existing function name at this address, if not create the function.
                    if (idc.GetFunctionName(startAddr) == ""):
                        # Try to create the function name name it.
                        if (idc.MakeFunction(startAddr) != 0):
                            set_name(startAddr, funcName)
                            print "Found \'%s\'..." % funcName
                            #print "LibTomCrypt::labelFunction(): addr=0x%08x" % startAddr
                        else:
                            # Failed to make function.
                            print "LibTomCrypt::labelFunction(): Failed to make function for %s!" % keyword
                    else:
                        # The function already exists, just rename it.
                        set_name(startAddr, funcName)
                        print "Found \'%s\'..." % funcName
                else:
                    # Unable to find the function start.
                    print "LibTomCrypt::labelFunction(): Unable to find function start for %s!" % funcName

                # Break the loop, we only wanted the first entry.
                break
        else:
            print "LibTomCrypt::labelFunction(): No xrefs to %s string found, skipping function..." % keyword


def labelRSAFunctions(stringList):
    # rsa_decrypt_key.c
    labelFunction(stringList, "rsa_decrypt_key.c", "LTC_rsa_decrypt_key_ex")

    # rsa_encrypt_key.c
    labelFunction(stringList, "rsa_encrypt_key.c", "LTC_rsa_encrypt_key_ex")

    # rsa_export.c
    labelFunction(stringList, "rsa_export.c", "LTC_rsa_export")

    # rsa_exptmod.c
    labelFunction(stringList, "rsa_exptmod.c", "LTC_rsa_exptmod")

    # rsa_free.c
    labelFunction(stringList, "rsa_free.c", "LTC_rsa_free")

    # rsa_get_size.c
    labelFunction(stringList, "rsa_get_size.c", "LTC_rsa_get_size")

    # rsa_import.c
    labelFunction(stringList, "rsa_import.c", "LTC_rsa_import")

    # rsa_make_key.c
    labelFunction(stringList, "rsa_make_key.c", "LTC_rsa_make_key")

    # rsa_sign_hash.c
    labelFunction(stringList, "rsa_sign_hash.c", "LTC_rsa_sign_hash_ex")

    # rsa_sign_saltlen_get.c
    labelFunction(stringList, "rsa_sign_saltlen_get.c", "LTC_rsa_sign_saltlen_get_max_ex")

    # rsa_verify_hash.c
    labelFunction(stringList, "rsa_verify_hash.c", "LTC_rsa_verify_hash_ex")


def labelHashDescriptor(descName):
    # Try to find the string label for the hash descriptor.
    stringAddr = findString(descName, True)
    if (stringAddr == None):
        # Failed to find the string label for the hash descriptor.
        print "LibTomCrypt::labelHashDescriptor(): Failed to find descriptor for '%s', skipping hash..." % descName
        return

    # Build a list of xrefs to this string.
    xrefList = XrefsTo(stringAddr.ea, 0)
    if (xrefList == None):
        # No xrefs to the descriptor label string.
        print "LibTomCrypt::labelHashDescriptor(): Failed to find xrefs to string label '%s'!" % descName
        return

    # Loop through the xref list.
    for xref in xrefList:
        # Check to make sure this address is a data address and not a code address.
        if (xref.iscode != 0):  # 1 is code ref, 0 is data
            continue

        # Label the descriptor block.
        idc.MakeName(xref.frm, "LTC_%s_desc" % descName)
        print "Found hash descriptor for %s" % descName

        # Skip 0x54 bytes ahead and make some dwords which will be the vtable for the descriptor.
        idc.MakeDword(xref.frm + 0x54)  # init()
        idc.MakeDword(xref.frm + 0x58)  # process()
        idc.MakeDword(xref.frm + 0x5C)  # done()
        idc.MakeDword(xref.frm + 0x60)  # test()
        idc.MakeDword(xref.frm + 0x64)  # hmac_block()

        # Analyze the init function.
        initAddr = idc.Dword(xref.frm + 0x54)
        if (initAddr != 0):
            idc.MakeFunction(initAddr)
            set_name(initAddr, "LTC_%s_init" % descName)

        # Analyze the process function.
        processAddr = idc.Dword(xref.frm + 0x58)
        if (processAddr != 0):
            idc.MakeFunction(processAddr)
            set_name(processAddr, "LTC_%s_process" % descName)

        # Analyze the done function.
        doneAddr = idc.Dword(xref.frm + 0x5C)
        if (doneAddr != 0):
            idc.MakeFunction(doneAddr)
            set_name(doneAddr, "LTC_%s_done" % descName)

        # Analyze the test function.
        testAddr = idc.Dword(xref.frm + 0x60)
        if (testAddr != 0):
            idc.MakeFunction(testAddr)
            set_name(testAddr, "LTC_%s_test" % descName)

        # Analyze the hmac_block function.
        hmacAddr = idc.Dword(xref.frm + 0x64)
        if (hmacAddr != 0):
            idc.MakeFunction(hmacAddr)
            set_name(hmacAddr, "LTC_%s_hmac_block" % descName)

        # We found the hash descriptor so we can break the loop.
        return


def main():
    # Build the list of libtomcrypt strings.
    stringList = buildLTCStringList()
    if (len(stringList) == 0):
        # No LTC strings found in the module.
        print "No LibTomCrypt strings found in the module!"
        return

    # Label the rsa functions.
    labelRSAFunctions(stringList)

    # Label the CHC hash descriptor.
    labelHashDescriptor("chc_hash")

    # Label the SHA hash descriptors.
    labelHashDescriptor("sha224")
    labelHashDescriptor("sha256")
    labelHashDescriptor("sha384")
    labelHashDescriptor("sha512_224")
    labelHashDescriptor("sha512_256")  # We label these two first because they use sha512 functions.
    labelHashDescriptor("sha512")

    # Label the whirlpool hash descriptor.
    labelHashDescriptor("whirlpool")

    # Label the MD2/4/5 hash descriptors.
    labelHashDescriptor("md2")
    labelHashDescriptor("md4")
    labelHashDescriptor("md5")

    # Label the RMD128/160/256/320 hash descriptors.
    labelHashDescriptor("rmd128")
    labelHashDescriptor("rmd160")
    labelHashDescriptor("rmd256")
    labelHashDescriptor("rmd320")

    # Label the SHA1 hash descriptor.
    labelHashDescriptor("sha1")

    # Label the tiger hash descriptor.
    labelHashDescriptor("tiger")

    # Tell the user we are done.
    print "Done."


main()
