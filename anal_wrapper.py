from ctypes import cdll, Structure, c_int, c_double, c_uint, c_byte, c_char_p, c_uint64, c_uint32, c_int64, c_void_p, CFUNCTYPE, POINTER, sizeof, byref

class RAnalOpType(object):
    R_ANAL_OP_TYPE_CALL=3
    R_ANAL_OP_TYPE_MOV=9

class RAnalOp(object):
    def __init__(self, type_):
        self._type = type_

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other):
        return self._type == other._type

class _RAnalOp(Structure):
    _fields_ = [('mnemonic', c_char_p),
                ('addr', c_uint64),
                ('type', c_uint64),
                ('prefix', c_uint64),
                ('type2', c_uint64),
                ('group', c_int),
                ('stackop', c_int),
                ('cond', c_int),
                ('size', c_int),
                ('nopcode', c_int),
                ('cycles', c_int),
                ('failcycles', c_int),
                ('family', c_int),
                ('eob', c_int),
                ('delay', c_int),
                ('jump', c_uint64),
                ('jmp', c_uint64),
                ('fail', c_uint64),
                ('selector', c_uint32),
                ('ptr', c_int64),
                ('val', c_uint64),
                ('ptrsize', c_int),
                ('stackptr', c_int64),
                ('refptr', c_int),
                ('src', c_void_p*3),
                ('dst', c_void_p),
                ('next', c_void_p),
                ('padding', c_byte*80)
                #('esil')
                #('switch_op')
    ]

RAnalOpCallback = CFUNCTYPE(c_int, c_void_p, POINTER(_RAnalOp), c_uint64, c_char_p, c_int)

class RAnalPlugin(Structure):
    _fields_ = [('name', c_char_p),
                ('desc', c_char_p),
                ('license', c_char_p),
                ('arch', c_char_p),
                ('bits', c_int),
                # Some dummy items to get offset to the "op" member
                ('esil', c_int),
                ('fileformat_type', c_int),
                ('custom_fn_anal', c_int),
                ('init', c_void_p),
                ('fini', c_void_p),
                ('reset_counter', c_void_p),
                ('archinfo', c_void_p),
                ('op', RAnalOpCallback)]

class Anal(object):
    def __init__(self):
        self.lib = cdll.LoadLibrary('./anal_msp430x.dylib')
        self.plugin = RAnalPlugin.in_dll(self.lib, 'r_anal_plugin_msp430x')

    def analyze(self, data):
        expected_length = len(data) / 2

        op = _RAnalOp()
        actual_length = self.plugin.op(None,
                                       op,
                                       0,
                                       data.decode('hex'),
                                       expected_length)

        if expected_length == actual_length:
            return RAnalOp(op.type)
        else:
            print 'expected length %d, got length %d' \
                % (expected_length, actual_length)
            return None

if __name__ == '__main__':
    a=Anal()
    a.analyze('294a')
