from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.program.flatapi import FlatProgramAPI
# from ghidra.program.flatapi.FlatProgramAPI import toAddr, getFunctionAt, getFunctionContaining
from ghidra.python import PythonScript
from ghidra.program.model.data import PointerDataType
from ghidra.program.database.data import StructureDB
from ghidra.program.database.data import PointerDB
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.data import PointerDataType
from ghidra.app.plugin.core.datamgr.util import DataTypeUtils
# for getDataTypeTraceBackward and getDataTypeTraceForward
from ghidra.app.plugin.core.decompile.actions import FillOutStructureCmd
from ghidra.program.model.data import MetaDataType
# this class is pretty much all private, but has some functionality
# that would be useful if it was accessible
# from ghidra.app.plugin.core.decompile.actions import CreatePointerRelative
from .sym_mem import MemHandle

from __main__ import *

import string
from collections import defaultdict, namedtuple
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


pcode_op_alph = set(string.ascii_uppercase + string.digits + "_")
name_to_op_map = {i: getattr(PcodeOpAST, i) for i in dir(PcodeOpAST) if pcode_op_alph.issuperset(set(i))}
op_to_name_map = {v: k for k, v in name_to_op_map.items()}
addr_fact = currentProgram.getAddressFactory()
space_name_to_id_map = {i.getName(): i.getSpaceID() for i in addr_fact.getAllAddressSpaces()}
space_id_to_name_map = {v: k for k, v in space_name_to_id_map.items()}
default_addr_space = addr_fact.getDefaultAddressSpace()
PTR_SIZE = default_addr_space.getPointerSize()


def getSigned(varnode):
    mask = 0x80 << ((varnode.getSize() - 1) * 8)
    value = varnode.getOffset()
    if ((value & mask) != 0):
        value |= (0xffffffffffffffff << ((varnode.getSize() - 1) * 8))
    return value


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


def trace_composite_access_forward(vn):
    """
    Trace forward from the varnode to all of the accesses.
    a lot of the code here is directly from FillOutStructureCmd.java,
    as that command performs most of the algoritm that we want, it just
    doesn't try to enumerate dereferenced pointers or track reads/writes
    """

    PointerRef = namedtuple("PointerRef", ["varnode", "offset",
                                           "mem_handle"])

    def putOnList(output, offset, todoList, doneList, mem_handle):
        """
        Add a Varnode reference to the current work list to facilitate flow tracing.
        To prevent cycles, a separate of visited Varnodes is maintained
        @param output is the Varnode at the current point of flow
        @param offset is the relative offset of the Varnode to the root variable
        @param todoList is the current work list
        @param doneList is the visited list
        """
        if output in doneList:
            return
        # TODO: Maybe add read here
        todoList.append(PointerRef(output, offset, mem_handle))
        doneList.add(output)
        return

    def sanityCheck(offset, existingSize=0):
        # offsets shouldn't be negative
        if offset < 0:
            return False
        # do we have room in the structure
        # if offset < existingSize:
        #     return True
        # bigger than existing size; arbitrary cut-off to
        # prevent huge structures
        if offset > 0x1000:
            return False
        return True


    mem_handle = MemHandle(PTR_SIZE, vn)
    dt = None
    if vn.high is not None:
        dt = vn.high.dataType
    cfad = CompositeFieldAccessDescriptor(datatype=dt)
    cfad.mem_handle = mem_handle
    todoList = [PointerRef(vn, 0, mem_handle)]
    doneList = set()
    while todoList:
        current_ref = todoList.pop()
        if current_ref.varnode == None:
            continue
        cfad.add_accessed_vn(current_ref.varnode)
        descendant_ops = current_ref.varnode.getDescendants()
        for desc_op in descendant_ops:
            opcode = desc_op.opcode
            output = desc_op.getOutput()
            inputs = list(desc_op.getInputs())

            if opcode in [PcodeOpAST.INT_ADD, PcodeOpAST.INT_SUB]:
                curr_vn = inputs[0]
                offset_vn = inputs[1]
                if not offset_vn.isConstant():
                    log.warning("Non constant Varnode encountered for an INT_ADD or INT_SUB")
                    continue
                value = getSigned(offset_vn)
                if opcode == PcodeOpAST.INT_ADD:
                    offset = value
                else:
                    offset = -value

                # should this offset create a location in the structure?
                if sanityCheck(offset):
                    # don't add datatype here, as info is
                    # likely "uninformed"
                    putOnList(output, offset, todoList,
                              doneList, current_ref.mem_handle)

                access = VarNodePCodeAccess(offset, vn=offset_vn)
                cfad.add_access(access)
                continue

            if opcode == PcodeOpAST.PTRADD:
                # PTRADD is for array indexing
                dt = None
                composite_vn = inputs[0]
                high_composite_vn = composite_vn.high
                if high_composite_vn is not None:
                    dt = high_composite_vn.dataType

                # this check is from the original, but it halts
                # processing for PTRADD ops when 2/3 of the inputs
                # aren't const, so use the existing logic but add a
                # backup here
                if inputs[1].isConstant() and inputs[2].isConstant():
                    newOff = current_ref.offset + \
                            (getSigned(inputs[1]) * inputs[2].getOffset())
                    if sanityCheck(newOff):
                        putOnList(output, newOff, todoList,
                                  doneList, current_ref.mem_handle)
                        access = VarNodePCodeAccess(newOff,
                                                    datatype=dt,
                                                    vn=inputs[1])
                        cfad.add_access(access)
                        # componentMap.setMinimumSize(newOff)
                        # TODO: add mem_handle access
                        current_ref.mem_handle.add_read_at(newOff,
                                                           output.size)
                    continue

                offset_vn = inputs[1]
                # Substitute 0 as the offset for now, as the offset
                # is variable, but will start with current_ref.offset
                offset = 0
                newOff = current_ref.offset + offset
                access = VarNodePCodeAccess(newOff,
                                            datatype=dt, vn=offset_vn)
                cfad.add_access(access)
                current_ref.mem_handle.add_read_at(newOff,
                                                   output.size)
                # TODO: add mem_handle access
                putOnList(output, offset, todoList, doneList,
                          current_ref.mem_handle)
                continue

            if opcode == PcodeOpAST.PTRSUB:
                # PTRSUB is for struct/union accesses

                dt = None
                composite_vn = inputs[0]
                high_composite_vn = composite_vn.high
                if high_composite_vn is not None:
                    dt = high_composite_vn.dataType

                # old stuff from FillOutStructureCmd
                if inputs[1].isConstant():
                    subOff = current_ref.offset + getSigned(inputs[1])
                    if sanityCheck(subOff):
                        putOnList(output, subOff, todoList, doneList,
                                  current_ref.mem_handle)
                        # componentMap.setMinimumSize(subOff)
                        access = VarNodePCodeAccess(subOff,
                                                    datatype=dt,
                                                    vn=inputs[1])
                        cfad.add_access(access)
                        current_ref.mem_handle.add_read_at(subOff,
                                                           output.size)
                        # TODO: add mem_handle access
                    continue

                log.error("Non-const offset input to PTRSUB op")
                continue

            if opcode == PcodeOpAST.SEGMENTOP:
                # treat segment op as if it were a cast to complete
                # the value
                #   The segment adds in some unknown base value.
                # get output and add to the Varnode Todo list
                putOnList(output, current_ref.offset, todoList,
                          doneList, current_ref.mem_handle)
                # componentMap.setMinimumSize(current_ref.offset)
                continue

            if opcode == PcodeOpAST.LOAD:
                # read_vn = output
                # current_ref.mem_handle.add_read_at(current_ref.offset,
                #                        read_vn.length)

                # want a mem handle that is at offset
                # current_ref.offset from the current handle,
                outDt = FillOutStructureCmd.getDataTypeTraceForward(output)

                # if the type is just a normal c type e.g. uint, it is just a
                # read of that value
                if outDt is not None and not isinstance(outDt, PointerDataType):
                    current_ref.mem_handle.add_read_at(current_ref.offset, outDt.length)
                    continue
                # dt = outDt.dataType
                # if dt is not None and not isinstance(dt, PointerDataType):
                #     current_ref.mem_handle.add_read_at(current_ref.offset, dt.length)
                #     continue

                maybe_new_mem_handle = current_ref.mem_handle.get_or_add_ptr_at(current_ref.offset, output)
                # FIXME: size of read looks like it is wrong
                maybe_new_mem_handle.add_read_at(0,
                                                 output.size)
                # unlike a STORE op, a LOAD op could be a dereference
                # in a chain of pointers, so try to continue processing
                # to try to resolve the full chain
                putOnList(output, 0, todoList,
                          doneList, maybe_new_mem_handle)
                # NOTE: original code did a little bit more here
                # outDt = getDataTypeTraceForward(output);
                # componentMap.addDataType(currentRef.offset, outDt);
                # if (outDt != null) {
                #     loadPcodeOps.add(new OffsetPcodeOpPair(currentRef.offset, pcodeOp));
                # }
                continue

            if opcode == PcodeOpAST.STORE:
                # we only care about this store op if the pointer is
                # related to the current struct/slice, not the value
                # being written
                if desc_op.getSlot(current_ref.varnode) != 1:
                    continue
                # TODO: this might not be adding the write to the
                # TODO: correct mem_handle

                # FIXME: do we want to differentiate between writes
                # FIXME: to this structure vs writes from this
                # FIXME: structure?

                # want a mem handle that is at offset
                # current_ref.offset from the current handle,
                maybe_new_mem_handle = current_ref.mem_handle.get_or_add_ptr_at(current_ref.offset, current_ref.varnode)
                maybe_new_mem_handle.add_write_at(0,
                                                  inputs[2].size)
                # NOTE: original code did a little bit more here
                # outDt = getDataTypeTraceBackward(inputs[2]);
                # componentMap.addDataType(currentRef.offset, outDt);

                # if (outDt != null) {
                #     storePcodeOps.add(new OffsetPcodeOpPair(currentRef.offset, pcodeOp));
                # }
                continue

            if opcode in [PcodeOpAST.COPY, PcodeOpAST.CAST]:
                putOnList(output, current_ref.offset, todoList,
                          doneList, current_ref.mem_handle)
                # if the input was an anchor vn, the output will be too
                # and should be treated as if it is the same vn
                if current_ref.mem_handle.is_anchor(inputs[0]):
                    current_ref.mem_handle.add_vn_anchor(current_ref.varnode)
                continue

            if opcode == PcodeOpAST.MULTIEQUAL:
                putOnList(output, current_ref.offset, todoList,
                          doneList, current_ref.mem_handle)
                if any([current_ref.mem_handle.is_anchor(i) for i in inputs]):
                    current_ref.mem_handle.add_vn_anchor(current_ref.varnode)
                continue

            if opcode == PcodeOpAST.CALL:
                # If pointer is passed directly (no offset)
                # find it as an input
                # TODO: maybe add mem_handle read here for params if
                # TODO: a load isn't used right before this
                if current_ref.offset == 0:
                    slot = desc_op.getSlot(current_ref.varnode)
                    if slot > 0 and slot < desc_op.getNumInputs():
                        pass
                else:
                    pass

                continue
            if opcode == PcodeOpAST.CALLIND:
                # TODO: maybe add mem_handle read here for params if
                # TODO: a load isn't used right before this
                continue

            if opcode == PcodeOpAST.INDIRECT:
                # TODO: This isn't really handled yet
                log.warning("Reached an INDIRECT op")
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
                continue

            if opcode in [PcodeOpAST.INT_EQUAL,
                          PcodeOpAST.INT_NOTEQUAL,
                          PcodeOpAST.INT_LESS,
                          PcodeOpAST.INT_SLESS,
                          PcodeOpAST.INT_LESSEQUAL,
                          PcodeOpAST.INT_SLESSEQUAL,
                          PcodeOpAST.INT_CARRY,
                          PcodeOpAST.INT_SCARRY,
                          PcodeOpAST.INT_SBORROW]:
                continue


            log.warning("Unhandled opcode %s", op_to_name_map.get(opcode, str(opcode)))
            raise Exception("Unhandled opcode")

    dt = None
    if vn.high is not None:
        dt = vn.high.dataType
    cfad.datatype = dt
    return cfad

def trace_composite_access_backward(vn):
    """
    This operates like a backward slice, except it will not follow
    all paths in the case of MULTIEQUAL (phi),

    similar operations can be found in
    FillOutStructureCmd.java
    """
    curr_vn = vn
    const_space_id = space_name_to_id_map['const']
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


        log.warning("Unhandled opcode %s", op_to_name_map.get(opcode, str(opcode)))
        raise Exception("Unhandled opcode")

    dt = None
    if curr_vn.high is not None:
        dt = curr_vn.high.dataType
    cfad.datatype = dt
    cfad.access_vns = cfad.access_vns[::-1]
    cfad.access_list = cfad.access_list[::-1]
    return cfad


class SliceUtils:
    """
    Utilities for getting slices, walking pointer chains, and associating
    vanodes with types.
    ./Features/Decompiler/ghidra_scripts/classrecovery/DecompilerScriptUtils.java appears to already contain some of the functions used here, oops.
    """

    def __init__(self, program, decomp_timeout=60):
        self.program = program
        self.addr_fact = self.program.getAddressFactory()
        self.dtm = self.program.getDataTypeManager()
        self._decomp_options = DecompileOptions()
        self._monitor = ConsoleTaskMonitor()
        self._ifc = DecompInterface()
        self._ifc.setOptions(self._decomp_options)
        self.fm = self.program.getFunctionManager()
        self.decomp_timeout = decomp_timeout

    def get_funcs_by_name(self, name):
        """
        Get all of the functions that match the name @name
        """
        return [i for i in self.fm.getFunctions(1) if i.name == name]

    def get_high_function(self, func, timeout=None):
        """
        Get a HighFunction for a given function
        """
        if timeout is None:
            timeout = self.decomp_timeout
        self._ifc.openProgram(func.getProgram())
        res = self._ifc.decompileFunction(func, timeout, self._monitor)
        high_func = res.getHighFunction()
        return high_func

    def get_high_sym_for_param(self, func, param_num):
        """
        Get the the high sym for param index. 1 indexed
        """
        high_func = self.get_high_function(func)
        prototype = high_func.getFunctionPrototype()
        num_params = prototype.getNumParams()
        if num_params == 0:
            return None
        high_sym_param = prototype.getParam(param_num-1)
        return high_sym_param

    def get_pcode_for_function(self, func):
        """
        Get Pcode ops for the function @func
        """
        hf = self.get_high_function(func)
        return list(hf.getPcodeOps())

    def get_fwd_slice_ops_and_vars_for_varnode(self, vn):
        """
        Get the pcode ops and varnodes associated with a forward
        slice from varnode @vn
        """
        fwd_vars = DecompilerUtils.getForwardSlice(vn)
        fwd_ops = DecompilerUtils.getForwardSliceToPCodeOps(vn)
        return fwd_ops, fwd_vars

    def get_fwd_slice_ops_and_vars_for_func_param(self, func, param_num):
        """
        Get the pcode ops and varnodes associated with a forward
        slice from @func's param @param_num, 1 indexed
        """
        fwd_ops = []
        fwd_vars = []
        high_sym = self.get_high_sym_for_param(func, param_num)
        if high_sym is None:
            log.warning("Unable to get high sym for %s param %d, this likely means that the function signature is not complete or it is an external function",
                        func.name, param_num)
            return fwd_ops, fwd_vars

        high_var = high_sym.getHighVariable()
        if high_var is None:
            log.warning("Unable to get high var for %s param %d, this likely means that the function signature is not complete or it is an external function",
                        func.name, param_num)
            return fwd_ops, fwd_vars
        for vn in high_var.getInstances():
            fops, fvars = self.get_fwd_slice_ops_and_vars_for_varnode(vn)
            fwd_ops += fops
            fwd_vars += fvars
        # dedup all ops and vars in case there were multiple instances
        return list(set(fwd_ops)), list(set(fwd_vars))

    def get_associated_pcode_op_inputs(self, op, varnodes):
        """
        Identify any input varnodes that are associated with the inputs
        to the specified pcode op.
        @op: pcode op
        @varnodes: list of Varnodes
        returns a list of indices and varnodes [(index, Varnode)]
        """
        inp_list = op.getInputs()
        inp_set = set(inp_list)
        intersecting = inp_set.intersection(varnodes)
        varnodes_and_inds = [(inp_list.index(i), i) for i in intersecting]
        return varnodes_and_inds

    def resolve_ptr_access(self, op, vn):
        """
        Pcode does not currently associate varnodes with given fields
        within a composite type (like a struct or union).
        That work appears to be done in VariableAccessDR.java
        and DecompilerDataTypeReferenceFinder.java
        while creating/enhancing clang tokens.

        The varnodes and pcode ops still exist, they just never actually
        have the clang tokens, and therefore the field names)
        associated with them

        Identifying the field name for a varnode can be done by
        walking up the chain of def-uses to a PTRSUB or PTRADD if one
        exists, or LOAD, CAST, COPY, INT_ADD, INT_SUB, etc. if a PTRADD
        or PTRSUB doesn't exist. This is more-or-less a backward slice.
        and original data source for a varnode

        """
        pass

