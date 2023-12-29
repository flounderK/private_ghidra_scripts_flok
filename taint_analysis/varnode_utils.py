def getSigned(varnode):
    mask = 0x80 << ((varnode.getSize() - 1) * 8)
    value = varnode.getOffset()
    if ((value & mask) != 0):
        value |= (0xffffffffffffffff << ((varnode.getSize() - 1) * 8))
    return value

