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

from __main__ import *

import string
from collections import defaultdict
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



class VarNodePCodeAccess:
    def __init__(self, offset, datatype=None):
        self.offset = offset
        self.datatype = datatype

    def str_access(self):
        if self.datatype is None:
            return " + %d" % offset
        base_dt = DataTypeUtils.getBaseDataType(self.datatype)
        component = base_dt.getComponentAt(self.offset)
        return "->%s" % component.fieldName


class CompositeAccessTracer:
    def __init__(self, varnode):
        self.vn = varnode
        self.has_high = self.vn.high is not None
        self.forward = False

    def trace_forward(self):
        """
        Trace forward from the varnode to all of the accesses
        """
        self.forward = True
        pass

    def trace_backward(self):
        curr_vn = self.vn
        collected_accesses = []
        while True:
            defining_op = curr_vn.getDef()
            if defining_op is None:
                dt = None
                if curr_vn.high is not None:
                    dt = curr_vn.high.dataType
                access = VarNodePCodeAccess(0, datatype=dt)
                collected_accesses.append(access)
                # TODO: fix accessor here
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
                if offset_vn.getSpace() != space_name_to_id_map['const']:
                    raise Exception("")
                offset = offset_vn.getOffset()
                access = VarNodePCodeAccess(offset, datatype=dt)
                collected_accesses.append(access)
                curr_vn = composite_vn
                continue

            log.warning("Unhandled opcode")
        return collected_accesses[::-1]


class SliceUtils:
    """
    Utilities for getting slices, walking pointer chains, and associating
    vanodes with types
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

