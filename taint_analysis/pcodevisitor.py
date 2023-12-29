
class PCodeVisitor(object):

    def __init__(self, **kw):
        super(PCodeVisitor, self).__init__()

    def visit(self, current_ref, pcode_op, *args, **kwargs):
        if pcode_op is None:
            return

        method_name = 'visit_%s' % pcode_op.mnemonic

        if hasattr(self, method_name):
            value = getattr(self, method_name)(current_ref, pcode_op, *args, **kwargs)
        else:
            value = getattr(self, 'visit_GENERIC')(current_ref, pcode_op, *args, **kwargs)

        return value

