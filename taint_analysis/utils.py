import string
from __main__ import *


def batch(it, sz):
    for i in range(0, len(it), sz):
        yield it[i:i+sz]


def hexdump_str(bytevals, offset=0, bytes_per_line=16, bytegroupsize=2):
    # get max address size
    max_address = len(bytevals) + offset
    curr_addr = max_address
    address_chr_count = 0
    while curr_addr > 0:
        curr_addr = curr_addr >> 4
        address_chr_count += 1

    if address_chr_count < 8:
        address_chr_count = 8

    num_spaces = ((bytes_per_line // bytegroupsize)-1)
    # 2 chars for each byte
    hex_byte_print_size = (bytes_per_line*2) + num_spaces

    # generate a line formatstring specifying max widths
    line_fmtstr = '%%0%dx: %%-%ds  %%s' % (address_chr_count,
                                           hex_byte_print_size)
    printable_char_ints = set(string.printable[:-5].encode())

    outlines = []
    for line_num, byteline in enumerate(batch(bytevals, bytes_per_line)):
        line_bytegroups = []
        line_strchrs = ""
        addr = (line_num*bytes_per_line) + offset
        for bytegroup in batch(byteline, bytegroupsize):
            bytegroup_str = ''.join(['%02x' % i for i in bytegroup])
            line_bytegroups.append(bytegroup_str)
            for b in bytegroup:
                # force the value to stay as a byte instead of converting
                # to an integer
                if b in printable_char_ints:
                    line_strchrs += chr(b)
                else:
                    line_strchrs += '.'
        hex_bytes = ' '.join(line_bytegroups)
        hex_bytes = hex_bytes.ljust(hex_byte_print_size, ' ')
        out_line = line_fmtstr % (addr, hex_bytes, line_strchrs)
        outlines.append(out_line)

    return '\n'.join(outlines)


def get_functions_called_by(func):
    """
    Get all of the functions that are called by @func
    """
    processed = set()
    to_process = [func]
    while to_process:
        curr = to_process.pop()
        if curr is None:
            continue
        for i in curr.getCalledFunctions(monitor):
            if i is None:
                continue
            if i in processed:
                continue
            if i in to_process:
                continue
            if i == curr:
                continue
            to_process.append(i)
        processed.add(curr)
    return processed
