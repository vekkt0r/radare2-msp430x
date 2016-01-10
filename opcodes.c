#include "opcodes.h"
#include "msp430x_disas.h"

static const opcode_table opcodes[] = {

        // Emulated instructions
	{"nop", 0x4303, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_NOP},
	{"ret", 0x4130, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_RET},
	{"adc", 0x6300, 0xff30, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_ADD},
	{"br", 0x4000, 0xf08f, MSP430_ADDR_AUTO, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_JMP},
	{"clr", 0x4300, 0xff30, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_MOV},
	{"clrc", 0xc312, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_MOV},
	{"clrn", 0xc222, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_MOV},
	{"clrz", 0xc322, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_MOV},
	{"dadc", 0xa300, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_ADD},
	{"dec", 0x8310, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_SUB},
	{"decd", 0x8320, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_SUB},
	{"dint", 0xc232, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_AND},
	{"eint", 0xd232, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_OR},
	{"inc", 0x5310, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_ADD},
	{"incd", 0x5320, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_ADD},
	{"pop", 0x4130, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_POP},
	{"rla", 0x5500, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_SAL},
	{"rlc", 0x6500, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_SHL},
	{"sbc", 0x7300, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_OR},
	{"setc", 0xd312, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_OR},
	{"setn", 0xd222, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_OR},
	{"setz", 0xd322, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_TWOOP, R_ANAL_OP_TYPE_OR},
	{"tst", 0x9300, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_CMP},

	// Two operand extended instructions
	{"mova", 0x0000, 0xf0f0, MSP430_ADDR_INDIRECT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_MOV},
	{"mova", 0x0010, 0xf0f0, MSP430_ADDR_INDIRECT_POST_INC, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_MOV},
	{"mova", 0x0020, 0xf0f0, MSP430_ADDR_ABS20, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_MOV},
	{"mova", 0x0030, 0xf0f0, MSP430_ADDR_INDEXED, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_MOV},
	{"mova", 0x0060, 0xf0f0, MSP430_ADDR_DIRECT, MSP430_ADDR_ABS20, MSP430_X, R_ANAL_OP_TYPE_MOV},
	{"mova", 0x0070, 0xf0f0, MSP430_ADDR_DIRECT, MSP430_ADDR_INDEXED, MSP430_X, R_ANAL_OP_TYPE_MOV},
	{"mova", 0x0080, 0xf0f0, MSP430_ADDR_IMM20, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_MOV},
	{"cmpa", 0x0090, 0xf0f0, MSP430_ADDR_IMM20, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_CMP},
	{"adda", 0x00a0, 0xf0f0, MSP430_ADDR_IMM20, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_ADD},
	{"suba", 0x00b0, 0xf0f0, MSP430_ADDR_IMM20, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SUB},
	{"mova", 0x00c0, 0xf0f0, MSP430_ADDR_DIRECT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_MOV},
	{"cmpa", 0x00d0, 0xf0f0, MSP430_ADDR_DIRECT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_CMP},
	{"adda", 0x00e0, 0xf0f0, MSP430_ADDR_DIRECT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_ADD},
	{"suba", 0x00f0, 0xf0f0, MSP430_ADDR_DIRECT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SUB},

	// One operand extended instructions
	{"rrcm.a", 0x0040, 0xf3f0, MSP430_ADDR_REPEAT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SHR},
	{"rram.a", 0x0140, 0xf3f0, MSP430_ADDR_REPEAT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SHR},
	{"rlam.a", 0x0240, 0xf3f0, MSP430_ADDR_REPEAT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SHL},
	{"rrum.a", 0x0340, 0xf3f0, MSP430_ADDR_REPEAT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SHL},
	{"rrcm", 0x0050, 0xf3f0, MSP430_ADDR_REPEAT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SHR},
	{"rram", 0x0150, 0xf3f0, MSP430_ADDR_REPEAT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SHR},
	{"rlam", 0x0250, 0xf3f0, MSP430_ADDR_REPEAT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SHL},
	{"rrum", 0x0350, 0xf3f0, MSP430_ADDR_REPEAT, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_SHR},

	// Third table extended
	// TODO: Should be able to do nicer decoding of these...
	{"calla", 0x13b0, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_IMM20, MSP430_X, R_ANAL_OP_TYPE_CALL},
	{"calla", 0x1380, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_ABS20, MSP430_X, R_ANAL_OP_TYPE_CALL},
	{"calla", 0x1370, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_INDIRECT_POST_INC, MSP430_X, R_ANAL_OP_TYPE_CALL},
	{"calla", 0x1360, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_INDIRECT, MSP430_X, R_ANAL_OP_TYPE_CALL},
	{"calla", 0x1340, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_CALL},
	{"calla", 0x1350, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_INDEXED, MSP430_X, R_ANAL_OP_TYPE_CALL},

	{"pushm.a", 0x1400, 0xff00, MSP430_ADDR_PUSHPOP, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_PUSH},
	{"pushm", 0x1500, 0xff00, MSP430_ADDR_PUSHPOP, MSP430_ADDR_DIRECT, MSP430_X, R_ANAL_OP_TYPE_PUSH},
	{"popm.a", 0x1600, 0xff00, MSP430_ADDR_PUSHPOP, MSP430_ADDR_POPM, MSP430_X, R_ANAL_OP_TYPE_POP},
	{"popm", 0x1700, 0xff00, MSP430_ADDR_PUSHPOP, MSP430_ADDR_POPM, MSP430_X, R_ANAL_OP_TYPE_POP},

	// Two operand instructio, R_ANAL_OP_TYPE_MOVns
	{"mov", 0x4000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_MOV},
	{"add", 0x5000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_ADD},
	{"addc", 0x6000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_ADD},
	{"subc", 0x7000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_SUB},
	{"sub", 0x8000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_SUB},
	{"cmp", 0x9000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_CMP},
	{"dadd", 0xa000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_ADD},
	{"bit", 0xb000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_CMP},
	{"bic", 0xc000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_AND},
	{"bis", 0xd000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_OR},
	{"xor", 0xe000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_XOR},
	{"and", 0xf000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP, R_ANAL_OP_TYPE_AND},

	// Jumps
	{"jnz", 0x2000, 0xfc00, MSP430_ADDR_NONE, MSP430_ADDR_JUMP, MSP430_JUMP, R_ANAL_OP_TYPE_CJMP},
	{"jz", 0x2400, 0xfc00, MSP430_ADDR_NONE, MSP430_ADDR_JUMP, MSP430_JUMP, R_ANAL_OP_TYPE_CJMP},
	{"jnc", 0x2800, 0xfc00, MSP430_ADDR_NONE, MSP430_ADDR_JUMP, MSP430_JUMP, R_ANAL_OP_TYPE_CJMP},
	{"jc", 0x2c00, 0xfc00, MSP430_ADDR_NONE, MSP430_ADDR_JUMP, MSP430_JUMP, R_ANAL_OP_TYPE_CJMP},
	{"jn", 0x3000, 0xfc00, MSP430_ADDR_NONE, MSP430_ADDR_JUMP, MSP430_JUMP, R_ANAL_OP_TYPE_CJMP},
	{"jge", 0x3400, 0xfc00, MSP430_ADDR_NONE, MSP430_ADDR_JUMP, MSP430_JUMP, R_ANAL_OP_TYPE_CJMP},
	{"jl", 0x3800, 0xfc00, MSP430_ADDR_NONE, MSP430_ADDR_JUMP, MSP430_JUMP, R_ANAL_OP_TYPE_CJMP},
	{"jmp", 0x3c00, 0xfc00, MSP430_ADDR_NONE, MSP430_ADDR_JUMP, MSP430_JUMP, R_ANAL_OP_TYPE_JMP},

	// One operand instructions
	{"rrc", 0x1000, 0xf380, MSP430_ADDR_NONE, MSP430_ADDR_ONEOP, MSP430_ONEOP, R_ANAL_OP_TYPE_SHR},
	{"swpb", 0x1080, 0xf380, MSP430_ADDR_NONE, MSP430_ADDR_ONEOP, MSP430_ONEOP, R_ANAL_OP_TYPE_MOV},
	{"rra", 0x1100, 0xf380, MSP430_ADDR_NONE, MSP430_ADDR_ONEOP, MSP430_ONEOP, R_ANAL_OP_TYPE_SHR},
	{"sxt", 0x1180, 0xf380, MSP430_ADDR_NONE, MSP430_ADDR_ONEOP, MSP430_ONEOP, R_ANAL_OP_TYPE_MOV},
	{"push", 0x1200, 0xf380, MSP430_ADDR_NONE, MSP430_ADDR_ONEOP, MSP430_ONEOP, R_ANAL_OP_TYPE_PUSH},
	{"call", 0x1280, 0xf380, MSP430_ADDR_NONE, MSP430_ADDR_ONEOP, MSP430_ONEOP, R_ANAL_OP_TYPE_CALL},
	{"reti", 0x1300, 0xf380, MSP430_ADDR_NONE, MSP430_ADDR_NONE, MSP430_ONEOP, R_ANAL_OP_TYPE_RET},

	// Do not remove
	{},
};

const opcode_table* opcode_find(ut16 instruction) {
	const opcode_table* ot = &opcodes[0];
	while ((instruction & ot->mask) != ot->id) {
		if (ot->name[0] == '\0') {
			return NULL;
		}
		ot++;
	}
	return ot;
}
