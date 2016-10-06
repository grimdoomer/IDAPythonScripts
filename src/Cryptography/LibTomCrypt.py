"""
    Author: Ryan Miceli (ryan.miceli@gmail.com)

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

# Create our named tuple for the hash descriptors and initialize the descriptors for each hashing algorithm.
HashDescriptor = namedtuple('HashDescriptor', 'name, id, hashSize, blockSize, oid, oidLength')
CHC_HASH_DESC           = HashDescriptor("chc_hash", 12, 0, 0, [], 0)
SHA224_HASH_DESC        = HashDescriptor("sha224", 10, 28, 64, [2, 16, 840, 1, 101, 3, 4, 2, 4], 9)
SHA256_HASH_DESC        = HashDescriptor("sha256", 0, 32, 64, [2, 16, 840, 1, 101, 3, 4, 2, 1], 9)
SHA384_HASH_DESC        = HashDescriptor("sha384", 4, 48, 128, [2, 16, 840, 1, 101, 3, 4, 2, 2], 9)
SHA512_HASH_DESC        = HashDescriptor("sha512", 5, 64, 128, [2, 16, 840, 1, 101, 3, 4, 2, 3], 9)
SHA512_224_HASH_DESC    = HashDescriptor("sha512-224", 15, 28, 128, [2, 16, 840, 1, 101, 3, 4, 2, 5], 9)
SHA512_256_HASH_DESC    = HashDescriptor("sha512-256", 16, 32, 128, [2, 16, 840, 1, 101, 3, 4, 2, 6], 9)
WHIRLPOOL_HASH_DESC     = HashDescriptor("whirlpool", 11, 64, 64, [1, 0, 10118, 3, 0, 55], 6)
MD2_HASH_DESC           = HashDescriptor("md2", 7, 16, 16, [1, 2, 840, 113549, 2, 2], 6)
MD4_HASH_DESC           = HashDescriptor("md4", 6, 16, 64, [1, 2, 840, 113549, 2, 4], 6)
MD5_HASH_DESC           = HashDescriptor("md5", 3, 16, 64, [1, 2, 840, 113549, 2, 5], 6)
RMD128_HASH_DESC        = HashDescriptor("rmd128", 8, 16, 64, [1, 0, 10118, 3, 0, 50], 6)
RMD160_HASH_DESC        = HashDescriptor("rmd160", 9, 20, 64, [1, 3, 36, 3, 2, 1], 6)
RMD256_HASH_DESC        = HashDescriptor("rmd256", 13, 32, 64, [1, 3, 36, 3, 2, 3], 6)
RMD320_HASH_DESC        = HashDescriptor("rmd320", 14, 40, 64, [], 0)
SHA1_HASH_DESC          = HashDescriptor("sha1", 2, 20, 64, [1, 3, 14, 3, 2, 26], 6)
TIGER_HASH_DESC         = HashDescriptor("tiger", 1, 24, 64, [1, 3, 6, 1, 4, 1, 11591, 12, 2], 9)

# List of all hash descriptor blocks.
LTC_HASH_DESCRIPTORS = [CHC_HASH_DESC, SHA224_HASH_DESC, SHA256_HASH_DESC, SHA384_HASH_DESC, SHA512_HASH_DESC,
                        SHA512_224_HASH_DESC, SHA512_256_HASH_DESC, WHIRLPOOL_HASH_DESC, MD2_HASH_DESC,
                        MD4_HASH_DESC, MD5_HASH_DESC, RMD128_HASH_DESC, RMD160_HASH_DESC, RMD256_HASH_DESC,
                        RMD320_HASH_DESC, SHA1_HASH_DESC, TIGER_HASH_DESC]

# Initialize our named tuple for the cipher descriptors and initialize the descriptors for each encryption algorithm.
CipherDescriptor = namedtuple("CipherDescriptor", 'name, id, minKeyLength, maxKeyLength, blockLength, defaultRounds, '
                                                  'setupFunc, ecbEncryptFunc, ecbDecryptFunc, testFunc, doneFunc, '
                                                  'keysizeFunc')
RIJNDAEL_CIPHER_DESC    = CipherDescriptor("rijndael", 6, 16, 32, 16, 10, "rijndael_setup", "rijndael_ecb_encrypt",
                                           "rijndael_ecb_decrypt", "rijndael_test", "rijndael_done", "rijndael_keysize")
AES_CIPHER_DESC         = CipherDescriptor("aes", 6, 16, 32, 16, 10, "rijndael_setup", "rijndael_ecb_encrypt",
                                           "rijndael_ecb_decrypt", "rijndael_test", "rijndael_done", "rijndael_keysize")
SAFER_K64_CIPHER_DESC   = CipherDescriptor("safer-k64", 8, 8, 8, 8, 6, "safer_k64_setup", "safer_ecb_encrypt",
                                           "safer_ecb_decrypt", "safer_k64_test", "safer_done", "safer_k64_keysize")
SAFER_SK64_CIPHER_DESC  = CipherDescriptor("safer-sk64", 9, 8, 8, 8, 8, "safer_sk64_setup", "safer_ecb_encrypt",
                                           "safer_ecb_decrypt", "safer_sk64_test", "safer_done", "safer_64_keysize")
SAFER_K128_CIPHER_DESC = CipherDescriptor("safer-k128", 10, 16, 16, 8, 10, "safer_k128_setup", "safer_ecb_encrypt",
                                           "safer_ecb_decrypt", "safer_sk128_test", "safer_done", "safer_128_keysize")
SAFER_SK128_CIPHER_DESC = CipherDescriptor("safer-sk128", 11, 16, 16, 8, 10, "safer_sk128_setup", "safer_ecb_encrypt",
                                           "safer_ecb_decrypt", "safer_sk128_test", "safer_done", "safer_128_keysize")
SAFER_PLUS_CIPHER_DESC  = CipherDescriptor("safer+", 4, 16, 32, 16, 8, "saferp_setup", "saferp_ecb_encrypt",
                                           "saferp_ecb_decrypt", "saferp_test", "saferp_done", "saferp_keysize")
TWOFISH_CIPHER_DESC     = CipherDescriptor("twofish", 7, 16, 32, 16, 16, "twofish_setup", "twofish_ecb_encrypt",
                                           "twofish_ecb_decrypt", "twofish_test", "twofish_done", "twofish_keysize")
ANUBIS_CIPHER_DESC      = CipherDescriptor("anubis", 19, 16, 40, 16, 12, "anubis_setup", "anubis_ecb_encrypt",
                                           "anubis_ecb_decrypt", "anubis_test", "anubis_done", "anubis_keysize")
BLOWFISH_CIPHER_DESC    = CipherDescriptor("blowfish", 0, 8, 56, 8, 16, "blowfish_setup", "blowfish_ecb_encrypt",
                                           "blowfish_ecb_decrypt", "blowfish_test", "blowfish_done", "blowfish_keysize")
CAMELLIA_CIPHER_DESC    = CipherDescriptor("camellia", 23, 16, 32, 16, 18, "camellia_setup", "camellia_ecb_encrypt",
                                           "camellia_ecb_decrypt", "camellia_test", "camellia_done", "camellia_keysize")
CAST5_CIPHER_DESC       = CipherDescriptor("cast5", 15, 5, 16, 8, 16, "cast5_setup", "cast5_ecb_encrypt",
                                           "cast5_ecb_decrypt", "cast5_test", "cast5_done", "cast5_keysize")
DES_CIPHER_DESC         = CipherDescriptor("des", 13, 8, 8, 8, 16, "des_setup", "des_ecb_encrypt", "des_ecb_decrypt",
                                           "des_test", "des_done", "des_keysize")
DES3_CIPHER_DESC        = CipherDescriptor("3des", 14, 24, 24, 8, 16, "des3_setup", "des3_ecb_encrypt",
                                           "des3_ecb_decrypt", "des3_test", "des3_done", "des3_keysize")
KASUMI_CIPHER_DESC      = CipherDescriptor("kasumi", 21, 16, 16, 8, 8, "kasumi_setup", "kasumi_ecb_encrypt",
                                           "kasumi_ecb_decrypt", "kasumi_test", "kasumi_done", "kasumi_keysize")
KHAZAD_CIPHER_DESC      = CipherDescriptor("khazad", 18, 16, 16, 8, 8, "khazad_setup", "khazad_ecb_encrypt",
                                           "khazad_ecb_decrypt", "khazad_test", "khazad_done", "khazad_keysize")
KSEED_CIPHER_DESC       = CipherDescriptor("seed", 20, 16, 16, 16, 16, "kseed_setup", "kseed_ecb_encrypt",
                                           "kseed_ecb_decrypt", "kseed_test", "kseed_done", "kseed_keysize")
MULTI2_CIPHER_DESC      = CipherDescriptor("multi2", 22, 40, 40, 8, 128, "multi2_setup", "multi2_ecb_encrypt",
                                           "multi2_ecb_decrypt", "multi2_test", "multi2_done", "multi2_keysize")
NOEKEON_CIPHER_DESC     = CipherDescriptor("noekeon", 16, 16, 16, 16, 16, "noekeon_setup", "noekeon_ecb_encrypt",
                                           "noekeon_ecb_decrypt", "noekeon_test", "noekeon_done", "noekeon_keysize")
RC2_CIPHER_DESC         = CipherDescriptor("rc2", 12, 8, 128, 8, 16, "rc2_setup", "rc2_ecb_encrypt", "rc2_ecb_decrypt",
                                           "rc2_test", "rc2_done", "rc2_keysize")
RC5_CIPHER_DESC         = CipherDescriptor("rc5", 2, 8, 128, 8, 12, "rc5_setup", "rc5_ecb_encrypt", "rc5_ecb_decrypt",
                                           "rc5_test", "rc5_done", "rc5_keysize")
RC6_CIPHER_DESC         = CipherDescriptor("rc6", 3, 8, 128, 16, 20, "rc6_setup", "rc6_ecb_encrypt", "rc6_ecb_decrypt",
                                           "rc6_test", "rc6_done", "rc6_keysize")
SKIPJACK_CIPHER_DESC    = CipherDescriptor("skipjack", 17, 10, 10, 8, 32, "skipjack_setup", "skipjack_ecb_encrypt",
                                           "skipjack_ecb_decrypt", "skipjack_test", "skipjack_done", "skipjack_keysize")
XTEA_CIPHER_DESC        = CipherDescriptor("xtea", 1, 16, 16, 8, 32, "xtea_setup", "xtea_ecb_encrypt",
                                           "xtea_ecb_decrypt", "xtea_test", "xtea_done", "xtea_keysize")

# List of all cipher descriptor blocks.
LTC_CIPHER_DESCRIPTORS = [RIJNDAEL_CIPHER_DESC, AES_CIPHER_DESC, SAFER_K64_CIPHER_DESC, SAFER_SK64_CIPHER_DESC,
                          SAFER_K128_CIPHER_DESC, SAFER_SK128_CIPHER_DESC, SAFER_PLUS_CIPHER_DESC, TWOFISH_CIPHER_DESC,
                          ANUBIS_CIPHER_DESC, BLOWFISH_CIPHER_DESC, CAMELLIA_CIPHER_DESC, CAST5_CIPHER_DESC,
                          DES_CIPHER_DESC, DES3_CIPHER_DESC, KASUMI_CIPHER_DESC, KHAZAD_CIPHER_DESC, KSEED_CIPHER_DESC,
                          MULTI2_CIPHER_DESC, NOEKEON_CIPHER_DESC, RC2_CIPHER_DESC, RC5_CIPHER_DESC, RC6_CIPHER_DESC,
                          SKIPJACK_CIPHER_DESC, XTEA_CIPHER_DESC]

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


def labelHashDescriptor(hashDesc):
    # Try to find the string label for the hash descriptor.
    stringAddr = findString(hashDesc.name, True)
    if (stringAddr == None):
        # Failed to find the string label for the hash descriptor.
        #print "LibTomCrypt::labelHashDescriptor(): Failed to find descriptor for '%s', skipping hash..." % hashDesc.name
        return

    # Build a list of xrefs to this string.
    xrefList = XrefsTo(stringAddr.ea, 0)
    if (xrefList == None):
        # No xrefs to the descriptor label string.
        print "LibTomCrypt::labelHashDescriptor(): Failed to find xrefs to string label '%s'!" % hashDesc.name
        return

    # Loop through the xref list.
    for xref in xrefList:
        # Check to make sure this address is a data address and not a code address.
        if (xref.iscode != 0):  # 1 is code ref, 0 is data
            continue

        # For better detection we are going to verify the whole hash descriptor.
        if (idc.Dword(xref.frm + 0x04) != hashDesc.id or idc.Dword(xref.frm + 0x08) != hashDesc.hashSize or
            idc.Dword(xref.frm + 0x0C) != hashDesc.blockSize):
            continue

        # Verify the OID matches the descriptor and then we can confirm we are in the right place.
        valid = True
        for i in range(0, hashDesc.oidLength):
            # Check the current OID value.
            if (idc.Dword(xref.frm + 0x10 + (i * 4)) != hashDesc.oid[i]):
                valid = False
                break

        # Check our status bit.
        if (valid == False):
            continue

        # Label the descriptor block.
        idc.MakeName(xref.frm, "LTC_%s_desc" % hashDesc.name)
        print "Found hash descriptor for %s" % hashDesc.name

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
            set_name(initAddr, "LTC_%s_init" % hashDesc.name)

        # Analyze the process function.
        processAddr = idc.Dword(xref.frm + 0x58)
        if (processAddr != 0):
            idc.MakeFunction(processAddr)
            set_name(processAddr, "LTC_%s_process" % hashDesc.name)

        # Analyze the done function.
        doneAddr = idc.Dword(xref.frm + 0x5C)
        if (doneAddr != 0):
            idc.MakeFunction(doneAddr)
            set_name(doneAddr, "LTC_%s_done" % hashDesc.name)

        # Analyze the test function.
        testAddr = idc.Dword(xref.frm + 0x60)
        if (testAddr != 0):
            idc.MakeFunction(testAddr)
            set_name(testAddr, "LTC_%s_test" % hashDesc.name)

        # Analyze the hmac_block function.
        hmacAddr = idc.Dword(xref.frm + 0x64)
        if (hmacAddr != 0):
            idc.MakeFunction(hmacAddr)
            set_name(hmacAddr, "LTC_%s_hmac_block" % hashDesc.name)

        # We found the hash descriptor so we can break the loop.
        return


def labelCipherDescriptor(cipherDesc):
    # Try to find the string label for the hash descriptor.
    stringAddr = findString(cipherDesc.name, True)
    if (stringAddr == None):
        # Failed to find the string label for the hash descriptor.
        #print "LibTomCrypt::labelCipherDescriptor(): Failed to find descriptor for '%s', skipping hash..." % cipherDesc.name
        return

    # Build a list of xrefs to this string.
    xrefList = XrefsTo(stringAddr.ea, 0)
    if (xrefList == None):
        # No xrefs to the descriptor label string.
        print "LibTomCrypt::labelCipherDescriptor(): Failed to find xrefs to string label '%s'!" % cipherDesc.name
        return

    # Loop through the xref list.
    for xref in xrefList:
        # Check to make sure this address is a data address and not a code address.
        if (xref.iscode != 0):  # 1 is code ref, 0 is data
            continue

        # For better detection we are going to verify the whole cipher descriptor.
        if (idc.Dword(xref.frm + 0x04) != cipherDesc.id or idc.Dword(xref.frm + 0x08) != cipherDesc.minKeyLength or
            idc.Dword(xref.frm + 0x0C) != cipherDesc.maxKeyLength or
                    idc.Dword(xref.frm + 0x10) != cipherDesc.blockLength or
                    idc.Dword(xref.frm + 0x14) != cipherDesc.defaultRounds):
            continue

        # Label the descriptor block.
        idc.MakeName(xref.frm, "LTC_%s_desc" % cipherDesc.name)
        print "Found cipher descriptor for %s" % cipherDesc.name

        # Skip 0x18 bytes ahead and make some dwords which will be the vtable for the descriptor.
        idc.MakeDword(xref.frm + 0x18)  # setup()
        idc.MakeDword(xref.frm + 0x1C)  # ecb_encrypt()
        idc.MakeDword(xref.frm + 0x20)  # ecb_decrypt()
        idc.MakeDword(xref.frm + 0x24)  # test()
        idc.MakeDword(xref.frm + 0x28)  # done()
        idc.MakeDword(xref.frm + 0x2C)  # keysize()

        # Analyze the setup function.
        setupAddr = idc.Dword(xref.frm + 0x18)
        if (setupAddr != 0):
            idc.MakeFunction(setupAddr)
            set_name(setupAddr, "LTC_%s_setup" % cipherDesc.name)

        # Analyze the ecb_encrypt function.
        encryptAddr = idc.Dword(xref.frm + 0x1C)
        if (encryptAddr != 0):
            idc.MakeFunction(encryptAddr)
            set_name(encryptAddr, "LTC_%s_ecb_encrypt" % cipherDesc.name)

        # Analyze the ecb_decrypt function.
        decryptAddr = idc.Dword(xref.frm + 0x20)
        if (decryptAddr != 0):
            idc.MakeFunction(decryptAddr)
            set_name(decryptAddr, "LTC_%s_ecb_decrypt" % cipherDesc.name)

        # Analyze the test function.
        testAddr = idc.Dword(xref.frm + 0x24)
        if (testAddr != 0):
            idc.MakeFunction(testAddr)
            set_name(testAddr, "LTC_%s_test" % cipherDesc.name)

        # Analyze the done function.
        doneAddr = idc.Dword(xref.frm + 0x28)
        if (doneAddr != 0):
            idc.MakeFunction(doneAddr)
            set_name(doneAddr, "LTC_%s_done" % cipherDesc.name)

        # Analyze the keysize function.
        keysizeAddr = idc.Dword(xref.frm + 0x2C)
        if (keysizeAddr != 0):
            idc.MakeFunction(keysizeAddr)
            set_name(keysizeAddr, "LTC_%s_keysize" % cipherDesc.name)

        # We found the hash descriptor so we can break the loop.
        return


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


def main():
    # Build the list of libtomcrypt strings.
    stringList = buildLTCStringList()

    # Label the rsa functions.
    labelRSAFunctions(stringList)

    # Loop through the list of hash descriptors and label each one.
    for hash in LTC_HASH_DESCRIPTORS:
        labelHashDescriptor(hash)

    # Loop through the list of cipher descriptors and label each one.
    for cipher in LTC_CIPHER_DESCRIPTORS:
        labelCipherDescriptor(cipher)

    # Tell the user we are done.
    print "Done."


main()
