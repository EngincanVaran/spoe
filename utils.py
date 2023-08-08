# Helper functions for static analyzer

import string

from shared import BASIC_BLOCKS


def is_hex(s):
    k = s
    if k == "":
        return False
    else:
        if k[:2] == "0x":
            k = k[2:]
        return all(c in string.hexdigits for c in k)


def hexLeadingZeroEreaser(hexText):
    result = ''
    try:
        if (hexText != None):
            result = hex(int(hexText, 0))
    except:
        # print('Error in hexLeadingZeroEreaser ')
        pass
    return result


def get_block_by_address(address: str):
    for block in BASIC_BLOCKS:
        if block.start_address == address:
            return block
    return None


# the function will convert all hex fields to standartformat like 0x00002457 to 0x2457
def convertAllHexBasicBlockFieldsToStandardFormat(Basic_Blocks):
    for block in Basic_Blocks:
        block.start_address = hexLeadingZeroEreaser(block.start_address)
        block.end_address = hexLeadingZeroEreaser(block.end_address)
        if block.jump_false_flag:
            block.jump_false_address = hexLeadingZeroEreaser(block.jump_false_address)
        if block.jump_true_flag:
            block.jump_true_address = hexLeadingZeroEreaser(block.jump_true_address)


def printBasicBlocks(basicBlocks):
    for k in basicBlocks:
        print("start_address:{} | end_address:{} | jump_t_flag:{} | jump_t_address:{} |\
            jump_f_flag:{} | jump_f_address:{} | fake_xrefs:{} | is_function_call:{} | call_jump_address:{} | calls:{} | xrefs_flag:{} | xrefs:{} |\
            fcns_flag:{} | fcns:{} | size:{} | index:{}\n\n".format(
            k.start_address, k.end_address, k.jump_true_flag, k.jump_true_address,
            k.jump_false_flag, k.jump_false_address, k.fake_xrefs, k.calls_flag, k.call_jump_address, k.calls,
            k.xrefs_flag, k.xrefs,
            k.fcns_flag, k.fcns, k.size, k.index))


def setNumberOfBytesBetweenAddresses(start_address, end_address):
    return int(end_address, 0) - int(start_address, 0)
