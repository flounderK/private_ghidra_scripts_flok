
from collections import defaultdict
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.app.plugin.core.datamgr.util import DataTypeUtils
from .trace import TraceArgs, get_or_create_traceargs_from_op
from .slice_utils import SliceUtils


class TaintArgs(TraceArgs):
    ALL_ARGS_MAP = {}

    def __init__(self, *args, **kwargs):
        super(TaintArgs, self).__init__(*args, **kwargs)
        self.tainted_args = {}


class TaintTracer(object):
    def __init__(self):
        self.tainted_varnodes_by_func_name = defaultdict(set)
        # call ops with tainted inputs by calling function name
        self.tainted_callops_by_func_name = defaultdict(set)
        # by calling function name
        self.taint_args_by_func_name = defaultdict(set)
        self.su = SliceUtils(currentProgram)

    def trace_func(self, taint_args):
        func = taint_args.called_func
        tainted_vns = []
        tainted_ops = []
        for k, v in taint_args.tainted_args.items():
            # TODO: confirm func isn't a thunk
            tops, tvars = self.su.get_fwd_slice_ops_and_vars_for_func_param(func, k)
            # TODO: maybe constrain vars and ops based on v, which
            # TODO: is probably a memhandle
            tainted_ops += tops
            tainted_vns += tvars

        # TODO: maybe add tainted globals here too

        tainted_ops_set = set(tainted_ops)
        tainted_vns_set = set(tainted_vns)

        # TODO: it would be beneficial to be able to create an acyclic call graph
        # TODO: to mark which functions write to a PTRSUB offset from one of their
        # TODO: parameters
        #

        curr_func_tainted_callops_set = self.tainted_callops_by_func_name[func.name]
        curr_func_tainted_call_args_set = self.taint_args_by_func_name[func.name]

        call_ops = [i for i in tainted_ops_set if i.opcode == PcodeOpAST.CALL]
        for op in call_ops:
            curr_func_tainted_callops_set
            slot_and_vns = self.su.get_associated_pcode_op_inputs(op, tainted_vns_set)
            new_taint_args = get_or_create_traceargs_from_op(op, TaintArgs)
            for slot, vn in slot_and_vns:
                new_taint_args.tainted_args[slot] = vn
            curr_func_tainted_call_args_set.add(new_taint_args)




        # self.su.get_associated_pcode_op_inputs
