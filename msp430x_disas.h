#ifndef MSP430X_DISAS_H
#define MSP430X_DISAS_H

#define MSP430_INSTR_MAXLEN	32

enum msp430_oneop_opcodes {
	MSP430_RCR,
	MSP430_SWPB,
	MSP430_RRA,
	MSP430_SXT,
	MSP430_PUSH,
	MSP430_CALL,
	MSP430_RETI,
	MSP430_UNUSED,
};

enum msp430_oneop_opcodes_x {
	MSP430_CALLA = 0x1,
	MSP430_PUSHM,
	MSP430_POPM,
};

enum msp430_jumps {
	MSP430_JNE,
	MSP430_JEQ,
	MSP430_JNC,
	MSP430_JC,
	MSP430_JN,
	MSP430_JGE,
	MSP430_JL,
	MSP430_JMP,
};

enum msp430_twoop_opcodes {
	MSP430_X,
	MSP430_JMP_OPC = 0x01,
	MSP430_MOV	= 0x4,
	MSP430_ADD,
	MSP430_ADDC,
	MSP430_SUBC,
	MSP430_SUB,
	MSP430_CMP,
	MSP430_DADD,
	MSP430_BIT,
	MSP430_BIC,
	MSP430_BIS,
	MSP430_XOR,
	MSP430_AND,
};

enum msp430_oneop_r_opcodes_x {
	MSP430_RRCM,
	MSP430_RRAM,
	MSP430_RLAM,
	MSP430_RRUM,
};

enum msp430_twoop_opcodes_x {
	MSP430_MOVA,
	MSP430_CMPA,
	MSP430_ADDA,
	MSP430_SUBA,
};

enum msp430_addr_modes {
	MSP430_DIRECT,
	MSP430_INDEXED,
	MSP430_INDIRECT,
	MSP430_INDIRECT_INC,
};

enum msp430_cmd_type {
	MSP430_ONEOP,
	MSP430_TWOOP,
	MSP430_JUMP,
};

enum msp430_registers {
	MSP430_PC,
	MSP430_SP,
	MSP430_SR,
	MSP430_R3,
	MSP430_R4,
	MSP430_R5,
	MSP430_R6,
	MSP430_R7,
	MSP430_R8,
	MSP430_R9,
	MSP430_R10,
	MSP430_R11,
	MSP430_R12,
	MSP430_R13,
	MSP430_R14,
	MSP430_R15,
};

struct msp430_cmd {
	ut8	type;
	ut16	opcode;
	st16	jmp_addr;
	ut16	call_addr;
	ut8	jmp_cond;
	char	instr[MSP430_INSTR_MAXLEN];
	char	operands[MSP430_INSTR_MAXLEN];
};

int msp430x_decode_command(const ut8 *instr, struct msp430_cmd *cmd);
#endif /* MSP430X_DISAS_H */
