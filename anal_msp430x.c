#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

#include "msp430x_disas.h"

typedef struct {
	char name[8];
	_RAnalOpType type;
} opcode_type_table;

// TODO: Merge with table from msp430x_disassemble.c and move to separate file
static const opcode_type_table opcodes[] = {
	// One operand instructions
	{"rra", R_ANAL_OP_TYPE_ROR},
	{"rrc", R_ANAL_OP_TYPE_ROR},
	{"push", R_ANAL_OP_TYPE_PUSH},
	{"call", R_ANAL_OP_TYPE_CALL},
	{"calla", R_ANAL_OP_TYPE_CALL},
	{"reti", R_ANAL_OP_TYPE_RET},

	// Two operand instructions
	{"mov", R_ANAL_OP_TYPE_MOV},
	{"add", R_ANAL_OP_TYPE_ADD},
	{"addc", R_ANAL_OP_TYPE_ADD},
	{"subc", R_ANAL_OP_TYPE_SUB},
	{"sub", R_ANAL_OP_TYPE_SUB},
	{"cmp", R_ANAL_OP_TYPE_CMP},
	{"dadd", R_ANAL_OP_TYPE_ADD},
	{"bit", R_ANAL_OP_TYPE_AND},
	{"bic", R_ANAL_OP_TYPE_MOV},
	{"bis", R_ANAL_OP_TYPE_MOV},
	{"xor", R_ANAL_OP_TYPE_XOR},
	{"and", R_ANAL_OP_TYPE_AND},

	// Emulated instructions
	{"nop", R_ANAL_OP_TYPE_NOP},
	{"ret", R_ANAL_OP_TYPE_RET},
	//{"br",   R_ANAL_OP_TYPE_},
	{"clr", R_ANAL_OP_TYPE_MOV},
	{"clrc", R_ANAL_OP_TYPE_MOV},
	{"clrn", R_ANAL_OP_TYPE_MOV},
	{"clrz", R_ANAL_OP_TYPE_MOV},
	{"dadc", R_ANAL_OP_TYPE_ADD},
	{"dec", R_ANAL_OP_TYPE_SUB},
	{"decd", R_ANAL_OP_TYPE_SUB},
	{"dint", R_ANAL_OP_TYPE_MOV},
	{"eint", R_ANAL_OP_TYPE_MOV},
	{"inc", R_ANAL_OP_TYPE_ADD},
	{"incd", R_ANAL_OP_TYPE_ADD},
	{"pop", R_ANAL_OP_TYPE_POP},
	{"rla", R_ANAL_OP_TYPE_SAL},
	{"rlc", R_ANAL_OP_TYPE_SAR},
	{"sbc", R_ANAL_OP_TYPE_SUB},
	{"setc", R_ANAL_OP_TYPE_ADD},
	{"setn", R_ANAL_OP_TYPE_ADD},
	{"setz", R_ANAL_OP_TYPE_ADD},
	{"tst", R_ANAL_OP_TYPE_CMP},

};

static int msp430x_op (RAnal *anal, RAnalOp *op, ut64 addr,
		       const ut8 *buf, int len) {
	int ret;
	struct msp430_cmd cmd;
	size_t i;

	memset (&cmd, 0, sizeof(cmd));
	memset (op, 0, sizeof(RAnalOp));

	ret = op->size = msp430x_decode_command (buf, &cmd);

	if (ret < 0) {
		return ret;
	}

	op->addr = addr;
	op->jump = op->fail = UT64_MAX;
	op->ptr = op->val = -1;

	// TODO: Re-write this completely, just a quick-n-dirty way of
	// getting somewhat working analysis with xrefs for the most
	// obvious stuff in r2. Probably a lot of things missing

	switch (cmd.type) {
	case MSP430_JUMP:
		if (strcmp("jmp", cmd.instr) == 0) {
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

	for (i = 0; i < sizeof(opcodes) / sizeof(&opcodes[0]); i++) {
		if (strncmp (cmd.instr, opcodes[i].name, 8) == 0) {
			op->type = opcodes[i].type;
			break;
		}
	}

	if (strcmp ("call", cmd.instr) == 0) {
		op->jump = cmd.jmp_addr;
		op->fail = addr + op->size;
		if (op->jump == 0) {
			op->type = R_ANAL_OP_TYPE_UCALL;
		}
	} else if (strcmp ("calla", cmd.instr) == 0) {
		op->jump = cmd.ptr_addr;
		op->fail = addr + op->size;
		if (op->jump == 0) {
			op->type = R_ANAL_OP_TYPE_UCALL;
		}
	} else if (strcmp ("mov", cmd.instr) == 0) {
		op->ptr = cmd.ptr_addr;
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
