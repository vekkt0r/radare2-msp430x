#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

#include "msp430x_disas.h"

static int msp430x_op (RAnal *anal, RAnalOp *op, ut64 addr,
		       const ut8 *buf, int len) {
	int ret;
	struct msp430_cmd cmd;

	memset (&cmd, 0, sizeof(cmd));
	memset (op, 0, sizeof(RAnalOp));

	ret = op->size = msp430x_decode_command (buf, &cmd);

	if (ret < 0) {
		return ret;
	} else if (ret > len) {
		return -1;
	}

	op->addr = addr;
	op->jump = op->fail = UT64_MAX;
	op->ptr = op->val = -1;
	op->type = cmd.op->radare_type;

	switch (op->type) {
	case R_ANAL_OP_TYPE_CJMP:
		if (cmd.jmp_addr) {
			op->jump = addr + cmd.jmp_addr;
		} else {
			op->type = R_ANAL_OP_TYPE_UCJMP;
		}
		op->fail = addr + 2;
		break;
	case R_ANAL_OP_TYPE_MOV:
		if (cmd.ptr_addr) {
			op->ptr = cmd.ptr_addr;
		}
		break;
	case R_ANAL_OP_TYPE_CALL:
		if (cmd.jmp_addr) {
			op->jump = cmd.jmp_addr;
		} else {
			op->type = R_ANAL_OP_TYPE_UCALL;
		}

		op->fail = addr + op->size;
		break;
	}

	return ret;
}

RAnalPlugin r_anal_plugin_msp430x = {
	.name = "msp430x",
	.desc = "TI MSP430X code analysis plugin",
	.license = "MIT",
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
