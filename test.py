import unittest
import subprocess

class TestDisas(unittest.TestCase):
    def dis(self, ops):
        return subprocess.check_output('rasm2 -a msp430xx -d %s' % ops,
                                       shell=True).rstrip()

    def test_mov(self):
        self.assertEqual(self.dis('294a'), 'mov @r10, r9')

    def helper_test_set(self, ops):
        for k, v in ops.iteritems():
            print 'testing \'%s\'' % k
            self.assertEqual(self.dis(k), v)

    def test_standard(self):
        ops = {
            '294a': 'mov @r10, r9',
            '295a': 'add @r10, r9',
            '296a': 'addc @r10, r9',
            '1a4072a3': 'mov 0xa372(r0), r10', # PC relative
            '0a49': 'mov r9, r10',
            '3a402211': 'mov #0x1122, r10',
            '1a422211': 'mov &0x1122, r10',
            '2a4a': 'mov @r10, r10',
            '3a4a': 'mov @r10+, r10',
            '0b4a': 'mov r10, r11',
            '824a2211': 'mov r10, &0x1122',
            '894a0000': 'mov r10, 0x0000(r9)',
        }
        self.helper_test_set(ops)

    def test_emulated(self):
        ops = {
            #'004a': 'bra r10',
        }
        self.helper_test_set(ops)

    def test_standard_with_extend(self):
        ops = {
            'c01819423020': 'movx &0x12030, r9',
            '4118824a3020': 'movx r10, &0x12030',
            #'411db240ccbb4423': 'movx #0xabbcc, &0x12344',
        }
        self.helper_test_set(ops)

    def test_extended(self):
        ops = {
            '090a': 'mova @r10, r9',
            '190a': 'mova @r10+, r9',
            '29013020': 'mova &0x12030, r9',
            '390a7b00': 'mova 0x007b(r10), r9',
            '39000c00': 'mova 0x000c(r0), r9',
            '39010c00': 'mova 0x000c(r1), r9',
            '29000c00': 'mova &0x000c, r9',
            '610a3020': 'mova r10, &0x12030',
            '790a7b00': 'mova r10, 0x007b(r9)',
            '79037b00': 'mova #0, 0x007b(r9)',
            '89013020': 'mova #0x12030, r9',
            '99013020': 'cmpa #0x12030, r9',
            'a9013020': 'adda #0x12030, r9',
            'b9013020': 'suba #0x12030, r9',
            'c90a': 'mova r10, r9',
            'd90a': 'cmpa r10, r9',
            'e90a': 'adda r10, r9',
            'f90a': 'suba r10, r9',
            '3a0012a3': 'mova 0xa312(r0), r10',
            '3a000ea3': 'mova 0xa30e(r0), r10',
            '3a000ca3': 'mova 0xa30c(r0), r10',
            '4a00': 'rrcm.a #1, r10',
            '4a05': 'rram.a #2, r10',
            '4a0a': 'rlam.a #3, r10',
            '4a0f': 'rrum.a #4, r10',
            '5a00': 'rrcm #1, r10',
            '5a05': 'rram #2, r10',
            '5a0a': 'rlam #3, r10',
            '5a0f': 'rrum #4, r10',
        }
        self.helper_test_set(ops)

if __name__ == '__main__':
    unittest.main()
