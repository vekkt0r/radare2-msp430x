import unittest
import subprocess

class TestDisas(unittest.TestCase):
    def dis(self, ops):
        return subprocess.check_output('LIBR_PLUGINS=. rasm2 -a msp430xx -d %s' % (ops),
                                       shell=True).rstrip()

    def test_mov(self):
        self.assertEqual(self.dis('294a'), 'mov @r10, r9')

    def helper_test_set(self, ops):
        for k, v in ops.iteritems():
            self.assertEqual(self.dis(k), v)

    def test_regressions(self):
        ops = {
            # Uninitalized operand
            '3441b01252803041' : 'pop r4\ncall #0x8052\nret'
        }
        self.helper_test_set(ops)

    def test_twoop(self):
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
            'b24011332211': 'mov #0x3311, &0x1122',
            '0a85': 'sub r5, r10',
            '0a75': 'subc r5, r10',
            '0a95': 'cmp r5, r10',
            '0aa5': 'dadd r5, r10',
            '5ab3': 'bit.b #1, r10',
            '1ab3': 'bit #1, r10',
            '1ac3': 'bic #1, r10',
            '1ad3': 'bis #1, r10',
            '0ae5': 'xor r5, r10',
            '0af5': 'and r5, r10',
            '8443faff': 'clr 0xfffa(r4)', # Should be a mov, not sure
                                          # why it's not emulated for
                                          # indexed destination
            '4e4f': 'mov.b r15, r14',
            'f24302c0': 'mov.b #-1, &0xc002',
            'b24302c0': 'mov #-1, &0xc002'
        }
        self.helper_test_set(ops)

    def test_jumps(self):
        ops = {
            '0120': 'jnz $+0x0004',
            '0124': 'jz $+0x0004',
            '0128': 'jnc $+0x0004',
            '012c': 'jc $+0x0004',
            '0130': 'jn $+0x0004',
            '0134': 'jge $+0x0004',
            '0138': 'jl $+0x0004',
            '013c': 'jmp $+0x0004',
            '5d3d': 'jmp $+0x02bc',
        }
        self.helper_test_set(ops)

    def test_oneops(self):
        ops = {
            '0a10': 'rrc r10',
            '1210aabb': 'rrc &0xbbaa',
            '2a10': 'rrc @r10',
            '3a10': 'rrc @r10+',
            '3a12': 'push @r10+',
            'ba10': 'swpb @r10+',
            'ba12': 'call @r10+',
            '0013': 'reti',
            '8911': 'sxt r9',
            'b01296c0': 'call #0xc096',
            'b212': 'call #8',
            'a212': 'call #4',
            'a312': 'call #2',
            '9312': 'call #1',
            '8312': 'call #0',
        }
        self.helper_test_set(ops)

    def test_emulated(self):
        ops = {
            '0343': 'nop',
            '0049': 'br r9',
            '3040baab': 'br #0xabba',
            '1042baab': 'br &0xabba',
            '0563': 'adc r5',
            '8263baab': 'adc &0xabba',
            '0543': 'clr r5',
            '12c3': 'clrc',
            '22c2': 'clrn',
            '22c3': 'clrz',
            '05a3': 'dadc r5',
            '1583': 'dec r5',
            '2583': 'decd r5',
            '32c2': 'dint',
            '32d2': 'eint',
            '1553': 'inc r5',
            '2553': 'incd r5',
            '3541': 'pop r5',
            '3041': 'ret',
            '0555': 'rla r5',
            '0565': 'rlc r5',
            '0573': 'sbc r5',
            '12d3': 'setc',
            '22d2': 'setn',
            '22d3': 'setz',
            '0593': 'tst r5',
        }
        self.helper_test_set(ops)

    def test_standard_with_extend(self):
        ops = {
            'c01819423020': 'movx &0x12030, r9',
            '4118824a3020': 'movx r10, &0x12030',
            '411db240ccbb4423': 'movx #0xabbcc, &0x12344',
            '411d9242ccbb4423': 'movx &0xabbcc, &0x12344',
            '411d9942ccbb4423': 'movx &0xabbcc, 0x12344(r9)',
            '411d9249ccbb4423': 'movx 0xabbcc(r9), &0x12344',
            '411d9240ccbb4423': 'movx 0xabbcc(r0), &0x12344',
            '4018b24302c0': 'movx #-1, &0xc002',
            '4a18c443faff': 'clrx.b 0xafffa(r4)',
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
            '4c181210aabb': 'rrcx &0xcbbaa',
            '40184a10': 'rrcx r10',
            '43184a10': '.rpt #4 rrcx r10',
            'c9184a10': '.rpt r9 rrcx r10',
            '43181a53': '.rpt #4 incx r10',
            '83131020': 'calla &0x32010',
            'b013feff': 'calla #0x0fffe',
            '5a137b00': 'calla 0x007b(r10)',
            '4a13': 'calla r10',
            '6a13': 'calla @r10',
            '7a13': 'calla @r10+',
            'e414': 'pushm.a #15, r4',
            '3414': 'pushm.a #4, r4',
            '3415': 'pushm #4, r4',
            '3116': 'popm.a #4, r4',
            '3117': 'popm #4, r4',
        }
        self.helper_test_set(ops)

if __name__ == '__main__':
    unittest.main()
