
from ghidra.program.model.pcode import PcodeOpAST
from .key_adjusted_offset_mapping import KeyAdjustedOffsetMapping
import logging
from __main__ import *

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


class MemHandle:
    ANCHOR_TO_HANDLE_MAP = {}

    def __init__(self, ptr_size=4, varnode=None, parent=None, offset=0):
        """
        @ptr_size: pointer size for the current program
        @varnode: optional anchor varnode that is a pointer to this MemHandle
        @parent: parent MemHandle to reflect reads and writes added to this
                 mem_handle on
        @offset: offset within parent where this MemHandle is located
        """
        self._base_offset = offset
        self._ptr_size = ptr_size
        self.parent = parent
        self._read_mask = bytearray(b'')
        self._write_mask = bytearray(b'')
        self.vn_anchors = []
        self.vn_anchor_set = set()
        self._curr_min_size = 0
        self._needs_size_calc = True
        self._needs_repr_resolve = True
        self._repr = None
        self.child_handles = []
        self._child_handle_map = {}
        if parent is None:
            self.ptr_map = KeyAdjustedOffsetMapping(offset)  # offset to MemHandle inst
            self.read_map = KeyAdjustedOffsetMapping(offset)  # offset to size
            self.write_map = KeyAdjustedOffsetMapping(offset)  # offset to size
            self.read_op_map = KeyAdjustedOffsetMapping(offset)  # offset to opcodes
            self.write_op_map = KeyAdjustedOffsetMapping(offset)  # offset to opcodes
            self.read_array_map = KeyAdjustedOffsetMapping(offset)  # offset to elem size
            self.read_array_op_map = KeyAdjustedOffsetMapping(offset)  # offset to opcodes
            # this may be excessive...
            self.const_index_read_array_map = KeyAdjustedOffsetMapping(offset)  # offset to elem size
            self.const_index_read_array_op_map = KeyAdjustedOffsetMapping(offset)  # offset to opcodes
        else:
            self.ptr_map = self.parent.ptr_map.new_child(offset)  # offset to MemHandle inst
            self.read_map = self.parent.read_map.new_child(offset)  # offset to size
            self.write_map = self.parent.write_map.new_child(offset)  # offset to size
            self.read_op_map = self.parent.read_op_map.new_child(offset)  # offset to opcodes
            self.write_op_map = self.parent.write_op_map.new_child(offset)  # offset to opcodes
            self.read_array_map = self.parent.read_array_map.new_child(offset)  # offset to elem size
            self.read_array_op_map = self.parent.read_array_op_map.new_child(offset)  # offset to opcodes
            self.const_index_read_array_map = self.parent.const_index_read_array_map.new_child(offset)  # offset to elem size
            self.const_index_read_array_op_map = self.parent.const_index_read_array_op_map.new_child(offset)  # offset to opcodes

        if varnode is not None:
            self.add_vn_anchor(varnode)

    def get_min_size(self):
        # caching size calc doesn't work for this because of the adjusted offset
        # mappings
        # if not self._needs_size_calc:
        #     return self._curr_min_size
        tmp_ptr_map = {k: self._ptr_size for k in self.ptr_map}
        curr_min_size = self._curr_min_size
        for map_inst in [self.read_map, self.write_map, tmp_ptr_map]:
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
                                          self.read_map,
                                          access_chr)
        if save:
            # no copy in py 2
            # make a copy so that changes to returned mask don't reflect
            # on internal mask
            self._read_mask = bytearray([i for i in read_mask])
        return read_mask

    def gen_write_mask(self, access_chr=b'\xff', save=True):
        write_mask = self._gen_access_mask(self._write_mask,
                                           self.write_map,
                                           access_chr)
        if save:
            # no copy in py 2
            # make a copy so that changes to returned mask don't reflect
            # on internal mask
            self._write_mask = bytearray([i for i in write_mask])
        return write_mask

    def gen_ptr_mask(self, access_chr=b'p'):
        tmp_ptr_map = {k: self._ptr_size for k in self.ptr_map}
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
            access_marks = access_marks.rjust(size, access_chr)
            # __setattribute__
            mask[access_start:access_end_non_incl] = access_marks
        return mask

    def add_read_at(self, offset, size, op=None):
        self._needs_size_calc = True
        self.read_map[offset] = size
        if op is None:
            return
        if self.read_op_map.get(offset) is None:
            self.read_op_map[offset] = []
        self.read_op_map[offset].append(op)

    def add_write_at(self, offset, size, op=None):
        self._needs_size_calc = True
        self.write_map[offset] = size
        if op is None:
            return
        if self.write_op_map.get(offset) is None:
            self.write_op_map[offset] = []
        self.write_op_map[offset].append(op)

    def add_ptr_at(self, offset, vn=None, mem_handle=None):
        """
        Create a new pointer at the given offset. If @mem_handle is not
        provided, create a new MemHandle instance.
        """
        self._needs_size_calc = True
        if mem_handle is None:
            mem_handle = MemHandle(self._ptr_size, vn)
        self.ptr_map[offset] = mem_handle
        return mem_handle

    def add_array_read_at(self, offset, size, op=None, const_index=False):
        """
        Similar to a normal read, but indicates that an access to the specified
        offset is being treated like an array access (PTRADD).
        """
        if const_index is True:
            read_array_map = self.const_index_read_array_map
            read_array_op_map = self.const_index_read_array_op_map
        else:
            read_array_map = self.read_array_map
            read_array_op_map = self.read_array_op_map

        read_array_map[offset] = size
        if op is None:
            return
        if read_array_op_map.get(offset) is None:
            read_array_op_map[offset] = []
        read_array_op_map[offset].append(op)

    def get_or_add_ptr_at(self, offset, vn=None):
        """
        Get the MemHandle pointer at @offset if it exists, or
        create a new one if it doesn't
        """
        maybe_mem_handle = self.ptr_map.get(offset)
        if maybe_mem_handle is not None:
            return maybe_mem_handle
        mem_handle = self.add_ptr_at(offset, vn)
        return mem_handle

    def add_vn_anchor(self, vn):
        if vn is None:
            return
        self._needs_repr_resolve = True
        self.vn_anchors.append(vn)
        self.vn_anchor_set.add(vn)
        self.ANCHOR_TO_HANDLE_MAP[vn] = self

    def resolve_repr(self):
        if self._repr is not None and self._needs_repr_resolve is False:
            return self._repr
        self._needs_repr_resolve = False
        initial_anchor = self.get_initial_anchor()
        if initial_anchor is None:
            self._repr = str(self)
            return str(self)
        high_vn = initial_anchor.high
        if high_vn is None:
            self._repr = str(self)
            return str(self)
        dt = high_vn.dataType
        name = high_vn.name
        min_size = self.get_min_size()
        repr_str = "MemHandle(%s %s, min_size=%d)" % (str(dt), str(name), min_size)
        self._repr = repr_str
        return repr_str

    def new_ref_to_offset(self, offset, vn=None):
        """
        Creates a new MemHandle instance with a unique relationship to the
        MemHandle instance whose `new_ref_to_offset` created it.
        Any reads, writes, or ptrs that are added to the new instance will
        have the additions reflected on all ancestors of the MemHandle
        instance, with an appropriate adjustment made to the offset of each
        addition.
        This is meant to make passing a reference to an embedded struct or
        buffer reasonable to work with
        """
        maybe_mem_handle = self._child_handle_map.get(offset)
        if maybe_mem_handle is not None:
            return maybe_mem_handle
        new_mem_handle = MemHandle(self._ptr_size, varnode=vn,
                                   parent=self, offset=offset)
        self.child_handles.append(new_mem_handle)
        self._child_handle_map[offset] = new_mem_handle
        return new_mem_handle

    def __repr__(self):
        return self.resolve_repr()

    def get_load_ops(self):
        return [i for i in sum([i for i in self.read_op_map.values()], []) if i.opcode == PcodeOpAST.LOAD]

    def get_store_ops(self):
        return [i for i in sum([i for i in self.write_op_map.values()], []) if i.opcode == PcodeOpAST.STORE]

