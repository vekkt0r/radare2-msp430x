#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

#include "msp430x_disas.h"

static int msp430x_op(RAnal *anal, RAnalOp *op, ut64 addr,
		      const ut8 *buf, int len)
{
	int ret;
	struct msp430_cmd cmd;

	memset (&cmd, 0, sizeof (cmd));
	memset (op, 0, sizeof (RAnalOp));

	ret = op->size = msp430x_decode_command (buf, &cmd);

	if (ret < 0) {
		return ret;
	}

	op->addr = addr;
	op->jump = op->fail = UT64_MAX;
	op->ptr = op->val = -1;

	switch (cmd.type) {
	case MSP430_ONEOP:
		switch (cmd.opcode) {
		case MSP430_RRA:
		case MSP430_RCR:
			op->type = R_ANAL_OP_TYPE_ROR; break;
		case MSP430_PUSH:
			op->type = R_ANAL_OP_TYPE_PUSH; break;
		case MSP430_CALL:
			op->type = R_ANAL_OP_TYPE_CALL; break;
		case MSP430_RETI:
			op->type = R_ANAL_OP_TYPE_RET; break;
		}
		break;
	case MSP430_TWOOP:
		case MSP430_BIT:
		case MSP430_BIC:
		case MSP430_BIS:
		case MSP430_MOV: op->type = R_ANAL_OP_TYPE_MOV; break;
		case MSP430_DADD:
		case MSP430_ADDC:
		case MSP430_ADD: op->type = R_ANAL_OP_TYPE_ADD; break;
		case MSP430_SUBC:
		case MSP430_SUB: op->type = R_ANAL_OP_TYPE_SUB; break;
		case MSP430_CMP: op->type = R_ANAL_OP_TYPE_CMP; break;
		case MSP430_XOR: op->type = R_ANAL_OP_TYPE_XOR; break;
		case MSP430_AND: op->type = R_ANAL_OP_TYPE_AND; break;
		break;
	case MSP430_JUMP:
		if (cmd.jmp_cond == MSP430_JMP) {
			op->type = R_ANAL_OP_TYPE_JMP;
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
		}
		op->jump = addr + cmd.jmp_addr;
		op->fail = addr + 2;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
	}

	return ret;
}

RAnalPlugin r_anal_plugin_msp430x = {
	.name = "msp430xx",
	.desc = "TI MSP430X code analysis plugin",
	.license = "LGPL3",
	.arch = "msp430x",
	.bits = 16,
	.op = msp430x_op,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_msp430x,
};
#endif
