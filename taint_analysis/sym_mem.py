
from .key_adjusted_offset_mapping import KeyAdjustedOffsetMapping
from __main__ import *


class MemHandleFactory:
    def __init__(self, program=None):
        if program is None:
            program = currentProgram
        self.program = program


class MemHandle:
    ANCHOR_TO_HANDLE_MAP = {}

    def __init__(self, ptr_size=4, varnode=None, offset=0):
        self._ptr_map = KeyAdjustedOffsetMapping(offset)  # offset to MemHandle inst
        self._ptr_size = ptr_size
        self._read_map = KeyAdjustedOffsetMapping(offset)  # offset to size
        self._write_map = KeyAdjustedOffsetMapping(offset)  # offset to size
        self._read_mask = bytearray(b'')
        self._write_mask = bytearray(b'')
        self.vn_anchors = []
        self.vn_anchor_set = set()
        self._curr_min_size = 0
        self._needs_size_calc = True
        if varnode is not None:
            self.add_vn_anchor(varnode)

    def get_min_size(self):
        if not self._needs_size_calc:
            return self._curr_min_size
        tmp_ptr_map = {k: self._ptr_size for k in self._ptr_map}
        curr_min_size = self._curr_min_size
        for map_inst in [self._read_map, self._write_map, tmp_ptr_map]:
            if len(map_inst) == 0:
                continue
            offset_key = max(list(map_inst.keys()))
            size = map_inst[offset_key]
            size_candidate = offset_key + size
            if curr_min_size < size_candidate:
                curr_min_size = size_candidate
        self._curr_min_size = curr_min_size
        self._needs_size_calc = False
        return self._curr_min_size

    def is_anchor(self, vn):
        return vn in self.vn_anchor_set

    def get_initial_anchor(self):
        if len(self.vn_anchors) > 0:
            return self.vn_anchors[0]
        return None

    def gen_read_mask(self, access_chr=b'\xff', save=True):
        read_mask = self._gen_access_mask(self._read_mask,
                                          self._read_map,
                                          access_chr)
        if save:
            # no copy in py 2
            # make a copy so that changes to returned mask don't reflect
            # on internal mask
            self._read_mask = bytearray([i for i in read_mask])
        return read_mask

    def gen_write_mask(self, access_chr=b'\xff', save=True):
        write_mask = self._gen_access_mask(self._write_mask,
                                           self._write_map,
                                           access_chr)
        if save:
            # no copy in py 2
            # make a copy so that changes to returned mask don't reflect
            # on internal mask
            self._write_mask = bytearray([i for i in write_mask])
        return write_mask

    def gen_ptr_mask(self, access_chr=b'p'):
        tmp_ptr_map = {k: self._ptr_size for k in self._ptr_map}
        ptr_mask = self._gen_access_mask(bytearray(b''),
                                         tmp_ptr_map,
                                         access_chr)
        return ptr_mask

    def _gen_access_mask(self, current_mask, access_map,
                         access_chr=b'\xff'):
        """
        generate a bytearray mask of the current accesses given
        an access map
        """
        # update size if a read/write/ptr has occurred since the
        # last min size calculation
        min_size = self.get_min_size()
        mask = current_mask.rjust(min_size, b'\x00')
        for offset, size in access_map.items():
            # non-inclusive end to access
            access_end_non_incl = offset + size
            access_end_incl = offset + size - 1
            access_start = offset
            # adjust the size of the mask so all accesses fit
            mask_len = len(mask)
            if mask_len < access_end_non_incl:
                diff = access_end_non_incl - mask_len
                mask = mask.rjust(access_end_non_incl, b'\x00')
            access_marks = b''
            # pointer markings
            # if offset in self._ptr_map:
            #     access_marks = access_marks.rjust(min(self._ptr_size,
            #                                       size),
            #                                       b'p')
            access_marks = access_marks.rjust(size, access_chr)
            # __setattribute__
            mask[access_start:access_end_non_incl] = access_marks
        return mask

    def add_read_at(self, offset, size):
        self._needs_size_calc = True
        self._read_map[offset] = size

    def add_write_at(self, offset, size):
        self._needs_size_calc = True
        self._write_map[offset] = size

    def add_ptr_at(self, offset, vn=None, mem_handle=None):
        self._needs_size_calc = True
        if mem_handle is None:
            mem_handle = MemHandle(self._ptr_size, vn)
        self._ptr_map[offset] = mem_handle
        return mem_handle

    def get_or_add_ptr_at(self, offset, vn=None):
        maybe_mem_handle = self._ptr_map.get(offset)
        if maybe_mem_handle is not None:
            return maybe_mem_handle
        mem_handle = self.add_ptr_at(offset, vn)
        return mem_handle

    def add_vn_anchor(self, vn):
        if vn is None:
            return
        self.vn_anchors.append(vn)
        self.vn_anchor_set.add(vn)
        self.ANCHOR_TO_HANDLE_MAP[vn] = self

    def resolve_repr(self):
        initial_anchor = self.get_initial_anchor()
        if initial_anchor is None:
            return str(self)
        high_vn = initial_anchor.high
        if high_vn is None:
            return str(self)
        dt = high_vn.dataType
        name = high_vn.name
        min_size = self.get_min_size()
        repr_str = "MemHandle(%s %s, min_size=%d)" % (str(dt), str(name), min_size)
        return repr_str


