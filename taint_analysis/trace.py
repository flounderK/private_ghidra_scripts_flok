from __main__ import *
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.plugin.core.decompile.actions import FillOutStructureCmd
from ghidra.program.model.data import MetaDataType
from ghidra.program.model.data import PointerDataType


from .pcodevisitor import PCodeVisitor
from .sym_mem import MemHandle
from .varnode_utils import getSigned

import string
from collections import defaultdict, namedtuple
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


_pcode_op_alph = set(string.ascii_uppercase + string.digits + "_")
NAME_TO_OP_MAP = {i: getattr(PcodeOpAST, i) for i in dir(PcodeOpAST) if _pcode_op_alph.issuperset(set(i))}
OP_TO_NAME_MAP = {v: k for k, v in NAME_TO_OP_MAP.items()}
# FIXME: probably shouldn't be using currentProgram without allowing user to specify program
_addr_fact = currentProgram.getAddressFactory()
SPACE_NAME_TO_ID_MAP = {i.getName(): i.getSpaceID() for i in _addr_fact.getAllAddressSpaces()}
SPACE_ID_TO_NAME_MAP = {v: k for k, v in SPACE_NAME_TO_ID_MAP.items()}
DEFAULT_ADDR_SPACE = _addr_fact.getDefaultAddressSpace()
PTR_SIZE = DEFAULT_ADDR_SPACE.getPointerSize()


class VarNodePCodeAccess:
    def __init__(self, offset, datatype=None, vn=None):
        self.offset = offset
        self.datatype = datatype
        self.vn = vn

    def get_byte_offset(self):
        if self.datatype:
            base_dt = DataTypeUtils.getBaseDataType(self.datatype)
            byte_offset = base_dt.length * self.offset
        else:
            byte_offset = self.offset
        return byte_offset

    def str_access(self):
        if self.datatype is None:
            return " + %d" % self.offset
        base_dt = DataTypeUtils.getBaseDataType(self.datatype)
        if hasattr(base_dt, "getComponentAt"):
            component = base_dt.getComponentAt(self.offset)
            return "->%s" % component.fieldName
        return " + %d" % self.offset


class CompositeFieldAccessDescriptor:
    """
    A class for describing the path to a field in a composite type.
    This class is meant to help with marking only specific fields of
    composite types as tainted in taint analysis, which will make
    taint propogation more accurate as it will allow functions like
    memcpy to taint passed in `dest`
    """
    def __init__(self, datatype=None):
        self.datatype = datatype
        self.access_list = []
        self.access_vns = []
        self.mem_handle = None

    def add_accessed_vn(self, vn):
        self.access_vns.append(vn)

    def add_access(self, access):
        self.access_list.append(access)

    def copy(self):
        new_cfad = CompositeFieldAccessDescriptor(self.datatype)
        new_cfad.access_list = [i for i in self.access_list]
        new_cfad.access_vns = [i for i in self.access_vns]
        new_cfad.mem_handle = self.mem_handle


class TraceArgs:
    """
    Object to help with consistently tracking values passed to functions
    called while tracing
    """
    def __init__(self, address=None):
        self.args = {}
        self.address = address

    def add_arg(self, arg, slot):
        self.args[slot] = arg

    def __repr__(self):
        param_repr = ",".join(["param_%d=%s" % (k, str(v)) for k, v in self.args.items()])
        return "TraceArgs(addr=%s, %s)" % (str(self.address), param_repr)


class TraceState:
    def __init__(self):
        self.callsite_to_args_map = {}
        self.accessed_vns = []

    def add_accessed_vn(self, vn):
        self.accessed_vns.append(vn)


PointerRef = namedtuple("PointerRef", ["varnode", "offset", "mem_handle"])


class ForwardSliceVisitor(PCodeVisitor):
    """
    A class for creating forward slices. It works like
    DecompilerUtils.getForwardSlice, except it is extensible with python
    classes and allows child classes to define their own handlers for
    any given op or unhandled ops with `visit_GENERIC`
    """
    PointerRef = namedtuple("PointerRef", ["varnode"])
    def __init__(self):
        self.todoList = []
        self.doneList = set()

    def clear_lists(self):
        self.todoList = []
        self.doneList = set()

    def putOnList(self, pointer_ref):
        """
        Add a Varnode reference to the current work list to facilitate flow tracing.
        To prevent cycles, a separate of visited Varnodes is maintained
        @param pointer_ref: a class with a `varnode` attribute
        """
        if pointer_ref.varnode in self.doneList:
            return False
        self.todoList.append(pointer_ref)
        self.doneList.add(pointer_ref.varnode)
        return True

    def trace(self, vn):
        """
        Trace forward from the varnode to all of the accesses.
        a lot of the code here is directly from FillOutStructureCmd.java,
        as that command performs most of the algoritm that we want, it just
        doesn't try to enumerate dereferenced pointers or track reads/writes
        """
        self.clear_lists()
        visited_ops = set()
        visited_varnodes = set()
        self.init_todoList(vn)
        while self.todoList:
            current_ref = self.todoList.pop()
            if current_ref.varnode == None:
                continue
            visited_varnodes.add(current_ref.varnode)
            self.pre_handle(current_ref)
            descendant_ops = current_ref.varnode.getDescendants()
            for desc_op in descendant_ops:
                self.visit(current_ref, desc_op)
                visited_ops.add(desc_op)
            self.post_op_handle(current_ref)

        return visited_ops, visited_varnodes

    def pre_handle(self, current_ref):
        """
        handler before iterating descendants
        """
        pass

    def init_todoList(self, vn):
        """
        add the initial PointerRef to the todoList
        """
        ptr_ref = self.PointerRef(vn)
        self.putOnList(ptr_ref)

    def post_op_handle(self, current_ref):
        """
        handler run after descending ops
        """
        pass

    def visit_CALL(self, current_ref, op):
        return

    def visit_CALLIND(self, current_ref, op):
        return

    def visit_GENERIC(self, current_ref, op):
        output = op.getOutput()
        if output is None:
            return
        ptr_ref = self.PointerRef(output)
        self.putOnList(ptr_ref)



class CompositeTrackForwardSliceVisitor(ForwardSliceVisitor):
    """
    A ForwardSliceVisitor that tracks accesses to PTR offsets from a varnode,
    similar to FillOutStructureCmd.
    """

    PointerRef = namedtuple("PointerRef", ["varnode", "offset", "mem_handle"])
    def __init__(self, mem_handle=None, **kwargs):
        super(CompositeTrackForwardSliceVisitor, self).__init__(**kwargs)
        self.address_to_call_input_map = {}
        self.vn_to_ptr_ref_map = {}
        self.start_mem_handle = mem_handle

    def putOnList(self, ptr_ref):
        if super(CompositeTrackForwardSliceVisitor, self).putOnList(ptr_ref):
            self.vn_to_ptr_ref_map[ptr_ref.varnode] = ptr_ref

    def sanityCheck(self, offset, existingSize=0):
        """
        Check to determine whether or not an INT_(ADD|SUB) or PTR(ADD|SUB)
        offset is considered valid
        """
        # offsets shouldn't be negative
        if offset < 0:
            log.error("Negative offset in sanityCheck")
            return False
        # do we have room in the structure
        # if offset < existingSize:
        #     return True
        # bigger than existing size; arbitrary cut-off to
        # prevent huge structures
        if offset > 0x1000:
            return False
        return True

    def init_todoList(self, vn):
        """
        add the initial PointerRef to the todoList
        """
        if self.start_mem_handle is None:
            self.start_mem_handle = MemHandle(PTR_SIZE, vn)
        self.putOnList(self.PointerRef(vn, 0, self.start_mem_handle))

    # deref and pure mov ops
    def visit_LOAD(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        log.debug("%s %s" % (str(current_ref.mem_handle), str(op)))
        outDt = FillOutStructureCmd.getDataTypeTraceForward(output)

        # if the type can't be resolved we know at the very least that
        # this is performing a read
        if outDt is None:
            current_ref.mem_handle.add_read_at(current_ref.offset, output.size, op=op)
            return

        # if the type is just a normal c type e.g. uint, it is just a
        # read of that value
        if outDt is not None and not isinstance(outDt, PointerDataType):
            current_ref.mem_handle.add_read_at(current_ref.offset, outDt.length, op=op)
            return

        current_ref.mem_handle.add_read_at(current_ref.offset,
                                           output.size, op=op)

        # A LOAD should be the only reason a truely new MemHandle is
        # created, all of the others should be child handles
        # TODO: something seems a little bit off with the new handle
        # TODO: creation here, it seems like the logic for determining
        # TODO: if this varnode can truely be treated as a pointer
        # TODO: could be improved
        # want a mem handle that is at offset
        # current_ref.offset from the current handle,
        maybe_new_mem_handle = current_ref.mem_handle.get_or_add_ptr_at(current_ref.offset, output)
        # unlike a STORE op, a LOAD op could be a dereference
        # in a chain of pointers, so try to continue processing
        # to try to resolve the full chain
        ptr_ref = self.PointerRef(output, 0, maybe_new_mem_handle)
        self.putOnList(ptr_ref)

    def visit_STORE(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())
        log.debug("%s %s" % (str(current_ref.mem_handle), str(op)))
        # we only care about this store op if the pointer is
        # related to the current struct/slice, not the value
        # being written
        if op.getSlot(current_ref.varnode) != 1:
            log.error("related STORE to different pointer %s" % (str(op)))
            return

        outDt = FillOutStructureCmd.getDataTypeTraceBackward(inputs[2])

        # if the type can't be resolved, record it as a write with the
        # best size that we can estimate
        if outDt is None:
            current_ref.mem_handle.add_write_at(current_ref.offset, inputs[2].size, op=op)
            return

        current_ref.mem_handle.add_write_at(current_ref.offset, outDt.length, op=op)

    def visit_COPY(self, current_ref, op):
        self._visit_add_anchor(current_ref, op)

    # call and return ops
    def visit_CALL(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        # If pointer is passed find it as an input
        slot = op.getSlot(current_ref.varnode)
        if slot > 0 and slot < op.getNumInputs():
            current_ref.mem_handle.add_read_at(current_ref.offset,
                                               op.getInput(slot).size,
                                               op=op)
            addr = op.getSeqnum().getTarget()
            if addr is not None:
                maybe_trace_args = self.address_to_call_input_map.get(addr)
                if maybe_trace_args is None:
                    maybe_trace_args = TraceArgs(addr)
                    self.address_to_call_input_map[addr] = maybe_trace_args
                maybe_trace_args.add_arg(current_ref, slot)

    def visit_CALLIND(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        slot = op.getSlot(current_ref.varnode)
        if slot > 0 and slot < op.getNumInputs():
            current_ref.mem_handle.add_read_at(current_ref.offset,
                                               op.getInput(slot).size,
                                               op=op)
            addr = op.getSeqnum().getTarget()
            if addr is not None:
                maybe_trace_args = self.address_to_call_input_map.get(addr)
                if maybe_trace_args is None:
                    maybe_trace_args = TraceArgs(addr)
                    self.address_to_call_input_map[addr] = maybe_trace_args
                maybe_trace_args.add_arg(current_ref, slot)

    # INT op handlers
    def visit_INT_ADD(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        self._visit_int_addsub(current_ref, op, inputs, output, PcodeOpAST.INT_ADD)

    def visit_INT_SUB(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        self._visit_int_addsub(current_ref, op, inputs, output, PcodeOpAST.INT_SUB)

    # phi ops
    def visit_MULTIEQUAL(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        ptr_ref = self.PointerRef(output, current_ref.offset, current_ref.mem_handle)
        self.putOnList(ptr_ref)
        if any([current_ref.mem_handle.is_anchor(i) for i in inputs]):
            current_ref.mem_handle.add_vn_anchor(output)

    # ptr calc ops
    def visit_PTRADD(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        # PTRADD is for array indexing
        log.debug("%s %s" % (str(current_ref.mem_handle), str(op)))
        # this check is from the original, but it halts
        # processing for PTRADD ops when 2/3 of the inputs
        # aren't const, so use the existing logic but add a
        # backup here
        const_index = False
        if inputs[1].isConstant() and inputs[2].isConstant():
            newOff = current_ref.offset + \
                    (getSigned(inputs[1]) * inputs[2].getOffset())
            if not self.sanityCheck(newOff):
                log.error("sanity check failed for %s" % str(op))
                return

            const_index = True
        else:

            # offset_vn = inputs[1]
            # Substitute 0 as the offset for now, as the offset
            # is variable, but will start with current_ref.offset
            offset = 0
            newOff = current_ref.offset + offset
        # no real mem_handle read here because this op is just
        # calculating the address of a future read or write
        offset_mem_handle = current_ref.mem_handle.new_ref_to_offset(newOff, output)
        ptr_ref = self.PointerRef(output, 0, offset_mem_handle)
        self.putOnList(ptr_ref)
        current_ref.mem_handle.add_array_read_at(newOff, inputs[2].size,
                                                 op=op, const_index=const_index)

    def visit_PTRSUB(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        # PTRSUB is for struct/union accesses
        log.debug("%s %s" % (str(current_ref.mem_handle), str(op)))

        if not inputs[1].isConstant():
            log.error("Non-const offset input to PTRSUB op")
            return

        # stuff from FillOutStructureCmd
        subOff = current_ref.offset + getSigned(inputs[1])
        if self.sanityCheck(subOff):
            # add a new item to the queue with a child mem handle so that
            # any LOADs or STOREs can be reflected correctly on this
            # MemHandle
            offset_mem_handle = current_ref.mem_handle.new_ref_to_offset(subOff, output)
            ptr_ref = self.PointerRef(output, 0, offset_mem_handle)
            self.putOnList(ptr_ref)
        else:
            log.error("sanityCheck failed for %s" % str(op))

    # mov-like ops
    def visit_CAST(self, current_ref, op):
        self._visit_add_anchor(current_ref, op)

    def visit_SEGMENTOP(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        # treat segment op as if it were a cast to complete
        # the value
        #   The segment adds in some unknown base value.
        # get output and add to the Varnode Todo list
        ptr_ref = self.PointerRef(output, current_ref.offset, current_ref.mem_handle)
        self.putOnList(ptr_ref)

    # other ops
    def visit_INDIRECT(self, current_ref, op):
        # TODO: This isn't really handled yet
        log.warning("Reached an INDIRECT op")

    def _visit_int_addsub(self, current_ref, op, inputs, output, opcode):
        # curr_vn = inputs[0]
        offset_vn = inputs[1]
        if not offset_vn.isConstant():
            # log.warning("Non constant Varnode encountered for an INT_ADD or INT_SUB")
            return
        value = getSigned(offset_vn)
        if opcode == PcodeOpAST.INT_ADD:
            offset = value
        else:
            offset = -value

        # should this offset create a location in the structure?
        if self.sanityCheck(offset):
            # don't add datatype here, as info is
            # likely "uninformed"
            self.putOnList(self.PointerRef(output, offset, current_ref.mem_handle))
        else:
            log.error("sanityCheck failed for %s" % str(op))

    def _visit_add_anchor(self, current_ref, op):
        output = op.getOutput()
        inputs = list(op.getInputs())

        ptr_ref = self.PointerRef(output, current_ref.offset, current_ref.mem_handle)
        self.putOnList(ptr_ref)
        # if the input was an anchor vn, the output will be too
        # and should be treated as if it is the same vn
        if current_ref.mem_handle.is_anchor(inputs[0]):
            current_ref.mem_handle.add_vn_anchor(output)


    def visit_GENERIC(self, current_ref, op):
        # output = op.getOutput()
        # inputs = list(op.getInputs())

        pass


class TaintTrackForwardSliceVisitor(ForwardSliceVisitor):
    def __init__(self, **kwargs):
        super(TaintTrackForwardSliceVisitor, self).__init__(**kwargs)
        self.tainted_call_args = defaultdict(list)
        self.tainted_varnodes_by_func_name = defaultdict(set)


class BackwardSliceVisitor(PCodeVisitor):
    """
    A class for creating backward slices. It works like
    DecompilerUtils.getBackwardSlice, except it is extensible with python
    classes and allows child classes to define their own handlers for
    any given op or unhandled ops with `visit_GENERIC`
    """
    PointerRef = namedtuple("PointerRef", ["varnode"])
    def __init__(self):
        self.todoList = []
        self.doneList = set()

    def clear_lists(self):
        self.todoList = []
        self.doneList = set()

    def putOnList(self, pointer_ref):
        """
        Add a Varnode reference to the current work list to facilitate flow tracing.
        To prevent cycles, a separate of visited Varnodes is maintained
        @param pointer_ref: a class with a `varnode` attribute
        """
        if pointer_ref.varnode in self.doneList:
            return False
        self.todoList.append(pointer_ref)
        self.doneList.add(pointer_ref.varnode)
        return True

    def trace(self, vn):
        """
        Trace backward from the varnode to find all of the defining ops
        """
        self.clear_lists()
        visited_ops = set()
        visited_varnodes = set()
        self.init_todoList(vn)
        while self.todoList:
            current_ref = self.todoList.pop()
            if current_ref.varnode == None:
                continue
            visited_varnodes.add(current_ref.varnode)
            self.pre_handle(current_ref)
            defining_op = current_ref.varnode.getDef()
            if defining_op is None:
                continue
            self.visit(current_ref, defining_op)
            visited_ops.add(defining_op)
            self.post_op_handle(current_ref)

        return visited_ops, visited_varnodes

    def pre_handle(self, current_ref):
        """
        handler before iterating descendants
        """
        pass

    def init_todoList(self, vn):
        """
        add the initial PointerRef to the todoList
        """
        ptr_ref = self.PointerRef(vn)
        self.putOnList(ptr_ref)

    def post_op_handle(self, current_ref):
        pass

    def visit_CALL(self, current_ref, op):
        return

    def visit_CALLIND(self, current_ref, op):
        return

    def visit_GENERIC(self, current_ref, op):
        for inp_vn in op.getInputs():
            if inp_vn is None:
                continue
            ptr_ref = self.PointerRef(inp_vn)
            self.putOnList(ptr_ref)


def trace_composite_access_backward(vn):
    """
    This operates like a backward slice, except it will not follow
    all paths in the case of MULTIEQUAL (phi),

    similar operations can be found in
    FillOutStructureCmd.java
    """
    curr_vn = vn
    const_space_id = SPACE_NAME_TO_ID_MAP['const']
    cfad = CompositeFieldAccessDescriptor()
    while True:
        cfad.add_accessed_vn(curr_vn)
        defining_op = curr_vn.getDef()
        if defining_op is None:
            # followed all the way back to source unless there is
            # an undefined type or uninitialized access or
            # it is just a parameter
            break
        opcode = defining_op.opcode
        if opcode in [PcodeOpAST.CALL, PcodeOpAST.CALLIND]:
            # vn is the output from a call or callind op,
            # can't really do much with that
            break

        if opcode in [PcodeOpAST.COPY, PcodeOpAST.CAST]:
            # NOTE: keeping this separate
            curr_vn = defining_op.getInput(0)
            continue
        if opcode == PcodeOpAST.LOAD:
            # TODO: handle deref
            derefd_vn = defining_op.getInput(1)
            curr_vn = derefd_vn
            continue

        if opcode in [PcodeOpAST.PTRSUB, PcodeOpAST.PTRADD]:
            # ptrsub is for struct/union accesses
            # ptradd is for array indexing
            composite_vn = defining_op.getInput(0)
            high_composite_vn = composite_vn.high
            if high_composite_vn is None:
                log.error("No high composite vn")
                break
            dt = high_composite_vn.dataType
            offset_vn = defining_op.getInput(1)
            if not offset_vn.isConstant():
                # This indicates that the op is a PTRADD.
                # Substitute 0 as the offset for now
                offset = 0
            else:
                offset = getSigned(offset_vn)
            access = VarNodePCodeAccess(offset, datatype=dt, vn=offset_vn)
            cfad.add_access(access)
            curr_vn = composite_vn
            continue
        if opcode == PcodeOpAST.MULTIEQUAL:
            # ideally all sources lead to the same place,
            # but for now just pick the first
            curr_vn = defining_op.getInput(0)
            continue

        if opcode == PcodeOpAST.INDIRECT:
            # TODO: This isn't really handled yet
            curr_vn = defining_op.getInput(0)
            log.warning("Reached an INDIRECT op")
            continue

        if opcode == PcodeOpAST.INT_ADD:
            # TODO: determine if vn is constant
            curr_vn = defining_op.getInput(0)
            offset_vn = defining_op.getInput(1)
            if offset_vn.getSpace() != const_space_id:
                log.warning("Non constant Varnode encountered for an INT_ADD")
                continue
            offset = offset_vn.getOffset()
            access = VarNodePCodeAccess(offset, vn=offset_vn)
            cfad.add_access(access)
            continue

        if opcode == PcodeOpAST.INT_SUB:
            curr_vn = defining_op.getInput(0)
            offset_vn = defining_op.getInput(1)
            if offset_vn.getSpace() != const_space_id:
                log.warning("Non constant Varnode encountered for an INT_SUB")
                continue
            offset = offset_vn.getOffset()
            access = VarNodePCodeAccess(offset, vn=offset_vn)
            cfad.add_access(access)
            continue

        if opcode in [PcodeOpAST.INT_2COMP, PcodeOpAST.INT_NEGATE,
                      PcodeOpAST.INT_XOR, PcodeOpAST.INT_AND,
                      PcodeOpAST.INT_OR, PcodeOpAST.INT_LEFT,
                      PcodeOpAST.INT_RIGHT, PcodeOpAST.INT_SRIGHT,
                      PcodeOpAST.INT_MULT, PcodeOpAST.INT_DIV,
                      PcodeOpAST.INT_REM, PcodeOpAST.INT_SDIV,
                      PcodeOpAST.PIECE, PcodeOpAST.SUBPIECE,
                      PcodeOpAST.INT_SREM, PcodeOpAST.BOOL_NEGATE,
                      PcodeOpAST.BOOL_XOR, PcodeOpAST.BOOL_AND,
                      PcodeOpAST.INT_SEXT, PcodeOpAST.INT_ZEXT,
                      PcodeOpAST.BOOL_OR]:
            curr_vn = defining_op.getInput(0)
            continue


        log.warning("Unhandled opcode %s", OP_TO_NAME_MAP.get(opcode, str(opcode)))
        raise Exception("Unhandled opcode")

    dt = None
    if curr_vn.high is not None:
        dt = curr_vn.high.dataType
    cfad.datatype = dt
    cfad.access_vns = cfad.access_vns[::-1]
    cfad.access_list = cfad.access_list[::-1]
    return cfad
