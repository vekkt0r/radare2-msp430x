#include <r_types.h>
#include <r_util.h>

#include "msp430x_disas.h"

typedef struct  {
	char name[8];
	ut16 id;
	ut16 mask;
	ut8  as;
	ut8  ad;
} opcode_table;


static const opcode_table oppocodo[] = {

	// Emulated instructions
	//{"bra",    0x0030, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_NONE},
	//{"bra",    0x0020, 0xf0ff, MSP430_ADDR_ABS20,    MSP430_ADDR_NONE},
	{"inc",    0x5310, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO},
	{"incd",   0x5320, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_AUTO},
	{"nop",    0x4303, 0xffff, MSP430_ADDR_NONE, MSP430_ADDR_NONE},

	// Two operand instructions
	{"mova",   0x0000, 0xf0f0, MSP430_ADDR_INDIRECT,   MSP430_ADDR_DIRECT},
	{"mova",   0x0010, 0xf0f0, MSP430_ADDR_INDIRECT_POST_INC, MSP430_ADDR_DIRECT},
	{"mova",   0x0020, 0xf0f0, MSP430_ADDR_ABS20,    MSP430_ADDR_DIRECT},
	{"mova",   0x0030, 0xf0f0, MSP430_ADDR_INDEXED,  MSP430_ADDR_DIRECT},
	{"mova",   0x0060, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_ABS20},
	{"mova",   0x0070, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_INDEXED},
	{"mova",   0x0080, 0xf0f0, MSP430_ADDR_IMM20,    MSP430_ADDR_DIRECT},
	{"cmpa",   0x0090, 0xf0f0, MSP430_ADDR_IMM20,    MSP430_ADDR_DIRECT},
	{"adda",   0x00a0, 0xf0f0, MSP430_ADDR_IMM20,    MSP430_ADDR_DIRECT},
	{"suba",   0x00b0, 0xf0f0, MSP430_ADDR_IMM20,    MSP430_ADDR_DIRECT},
	{"mova",   0x00c0, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_DIRECT},
	{"cmpa",   0x00d0, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_DIRECT},
	{"adda",   0x00e0, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_DIRECT},
	{"suba",   0x00f0, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_DIRECT},

	// One operand instructions
	{"rrcm.a", 0x0040, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT},
	{"rram.a", 0x0140, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT},
	{"rlam.a", 0x0240, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT},
	{"rrum.a", 0x0340, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT},
	{"rrcm",   0x0050, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT},
	{"rram",   0x0150, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT},
	{"rlam",   0x0250, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT},
	{"rrum",   0x0350, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT},

	// Third table
	{"calla", 0x1340, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_DIRECT},
	{"calla", 0x1350, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_INDEXED},

	{"pushm", 0x1400, 0xff00, MSP430_ADDR_NONE, MSP430_ADDR_REPEAT},

	// Normal stuffs
	{"mov",   0x4000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO},
	{"add",   0x5000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO},
	{"addc",  0x6000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO},

	// Jumps
	{"jnz",   0x2000, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP},
	{"jz",    0x2400, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP},
	{"jnc",   0x2800, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP},
	{"jc",    0x2c00, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP},
	{"jn",    0x3000, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP},
	{"jge",   0x3400, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP},
	{"jl",    0x3800, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP},
	{"jmp",   0x3c00, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP},

	// Oneops
	{"rrc",   0x1000, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP},
	{"swpb",  0x1080, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP},
	{"rra",   0x1100, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP},
	{"sxt",   0x1180, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP},
	{"push",  0x1200, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP},
	{"call",  0x1280, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP},
	{"reti",  0x1300, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_NONE},

	// Do not remove
	{'\0',     0,      0,     0},
};

static const char *two_op_instrs[] = {
	[MSP430_MOV]	= "mov",
	[MSP430_ADD]	= "add",
	[MSP430_ADDC]	= "addc",
	[MSP430_SUBC]	= "subc",
	[MSP430_SUB]	= "sub",
	[MSP430_CMP]	= "cmp",
	[MSP430_DADD]	= "dadd",
	[MSP430_BIT]	= "bit",
	[MSP430_BIC]	= "bic",
	[MSP430_BIS]	= "bis",
	[MSP430_XOR]	= "xor",
	[MSP430_AND]	= "and",
};

static const char *one_op_instrs[] = {
	[MSP430_RCR]	= "rcr",
	[MSP430_SWPB]	= "swpb",
	[MSP430_RRA]	= "rra",
	[MSP430_SXT]	= "sxt",
	[MSP430_PUSH]	= "push",
	[MSP430_CALL]	= "call",
	[MSP430_RETI]	= "reti",
};

static const char *jmp_instrs[] = {
	[MSP430_JEQ]	= "jeq",
	[MSP430_JNE]	= "jnz",
	[MSP430_JC]	= "jc",
	[MSP430_JNC]	= "jnc",
	[MSP430_JN]	= "jn",
	[MSP430_JGE]	= "jge",
	[MSP430_JL]	= "jl",
	[MSP430_JMP]	= "jmp",
};

static ut8 get_twoop_opcode(ut16 instr)
{
	return instr >> 12;
}

static int get_src (instr) {
	return (instr >> 8) & 0xF;
}

static int get_dst (instr) {
	return instr & 0xF;
}

static ut8 get_as(ut16 instr)
{
	return (instr >> 4) & 3;
}

static ut8 get_bw(ut16 instr)
{
	return (instr >> 6) & 1;
}

static ut8 get_ad(ut16 instr)
{
	return (instr >> 7) & 1;
}

static ut8 is_ext_word(ut16 instr)
{
	return ((instr >> 11) & 0x1f) == 3;
}

static void remove_first_operand (struct msp430_cmd *cmd)
{
	if (strchr (cmd->operands, ',')) {
		memmove (cmd->operands, strchr (cmd->operands, ',') + 2,
				strlen (strchr (cmd->operands, ',') + 2) + 1);
	}
}

static void remove_second_operand (struct msp430_cmd *cmd)
{
	if (strchr (cmd->operands, ','))
		*strchr (cmd->operands, ',') = '\0';
}

/* TODO: This is ugly as hell */
static int decode_emulation (ut16 instr, ut16 dst, struct msp430_cmd *cmd)
{
	int ret = -1;
	ut8 as, opcode;

	as = get_as (instr);
	opcode = get_twoop_opcode (instr);

	if (as == 0 && get_src (instr) == MSP430_R3 && opcode == MSP430_ADDC) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "adc.b" : "adc");
		snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#0, r%d",
				get_dst (instr));
	} else if (opcode == MSP430_MOV && as == 0 && get_src (instr) == MSP430_R3
			&& get_dst (instr) != MSP430_R3 && get_ad (instr) == 0) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "clr.b" : "clr");
		remove_first_operand (cmd);
	} else if (opcode == MSP430_MOV && as != 3 && get_dst (instr) == MSP430_PC
			&& get_src (instr) != MSP430_SP) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "br");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_BIC && as == 2 && get_src (instr) == MSP430_SR) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "clrn");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIC && as == 2 && get_src (instr) == 3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "clrz");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_DADD && as == 0 && get_src (instr) == MSP430_R3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "dadc.b" : "dadc");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_SUB && as == 1 && get_src (instr) == MSP430_R3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "dec.b" : "dec");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_SUB && as == 2 && get_src (instr) == MSP430_R3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "decd.b" : "decd");
		remove_first_operand (cmd);
	} else if (opcode == MSP430_BIC && as == 3 && get_src (instr) == MSP430_SR
			&& get_dst (instr) == MSP430_SR) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "dint");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIS && as == 3 && get_src (instr) == MSP430_SR
			&& get_dst (instr) == MSP430_SR) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", "eint");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_ADD && as == 1 && get_src (instr) == MSP430_R3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "inc.b" : "inc");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_ADD && as == 2 && get_src (instr) == MSP430_R3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "incd.b" : "incd");
		remove_first_operand (cmd);
	} else if (opcode == MSP430_XOR && as == 3 && get_src (instr) != MSP430_R3
			&& get_src (instr) != MSP430_SR && (dst == 0xFFFF || dst == 0xFF)) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "inv.b" : "inv");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_MOV && as == 0 && get_src (instr) == MSP430_R3
			&& get_ad (instr) == 0 && get_dst (instr) == 3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "nop");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_MOV && as == 3 && get_src (instr) == MSP430_SP
			&& get_dst (instr) != MSP430_PC) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "pop.b" : "pop");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_MOV && as == 3 && get_src (instr) == MSP430_SP
			&& get_dst (instr) == MSP430_PC) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "ret");
		cmd->type = MSP430_ONEOP;
		cmd->opcode = MSP430_RETI;
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_ADD && get_src (instr) == get_dst (instr)) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "rla.b" : "rla");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_ADDC && get_src (instr) == get_dst (instr)) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "rlc.b" : "rlc");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_SUBC && as == 0 && get_src (instr) == MSP430_R3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "sbc.b" : "sbc");
		remove_second_operand (cmd);
	} else if (opcode == MSP430_BIS && as == 1 && get_dst (instr) == MSP430_R3) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "setc");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIS && as == 2 && get_dst (instr) == MSP430_SR) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "setn");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_BIS && as == 2 && get_dst (instr) == MSP430_SR) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "setz");
		cmd->operands[0] = '\0';
	} else if (opcode == MSP430_CMP && as == 0 && get_src (instr) == MSP430_SR) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
				get_bw (instr) ? "tst.b" : "tst");
		remove_first_operand (cmd);
	}

	return ret;
}

static int decode_addressing_mode (ut16 instr, ut16 dst, ut16 op2, struct msp430_cmd *cmd)
{
	int ret;
	ut8 as, ad;
	char dstbuf[16];

	memset (dstbuf, 0, sizeof (dstbuf));

	as = get_as (instr);
	ad = get_ad (instr);

	switch (as) {
	case 0:
		switch (get_src (instr)) {
		case MSP430_R3:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#0");
			break;
		default:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
				"r%d", get_src (instr));
		}
		ret = 2;
		break;
	case 1:
		ret = 4;
		switch (get_src (instr)) {
		case MSP430_PC:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
				"0x%04x", dst);
			break;
		case MSP430_R3:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "%s", "#1");
			ret = 2;
			break;
		case MSP430_SR:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
				"&0x%04x", dst);
			break;
		default:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
				"0x%x(r%d)", dst, get_src (instr));
		}
		break;
	case 2:
		switch (get_src (instr)) {
		case MSP430_SR:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#4");
			break;
		case MSP430_R3:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#2");
			break;
		default:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
					"@r%d", get_src (instr));
		}

		ret = 2;
		break;
	case 3:
		ret = 2;
		switch (get_src (instr)) {
		case MSP430_SR:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#8");
			break;
		case MSP430_R3:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#-1");
			break;
		case MSP430_PC:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
					"#0x%04x", dst);
			ret = 4;
			break;
		default:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
					"@r%d+", get_src (instr));
		}
		break;
	default:
		ret = -1;
	}

	if (ret < 0)
		return ret;


	switch (ad) {
	case 0:
		snprintf (dstbuf, 15, ", r%d", get_dst (instr));
		break;
	case 1:
		switch (get_dst(instr)) {
		case MSP430_PC:
			snprintf (dstbuf, 15, ", 0x%04x", dst);
			if (ret == 2)
				ret = 4;
			break;
		case MSP430_SR:
			if ((as == 1 || as == 3) && (get_src (instr) == MSP430_PC
					|| get_src (instr) == 2)) {
				snprintf (dstbuf, 15, ", &0x%04x", op2);
				ret = 6;
			} else {
				snprintf (dstbuf, 15, ", &0x%04x", dst);
				ret = 4;
			}
			break;
		default:
			if ((as == 1 || as == 3) && get_src (instr) == MSP430_PC) {
				snprintf (dstbuf, 15, ", 0x%x(r%d)", op2, get_dst (instr));
				ret = 6;
			} else {
				snprintf (dstbuf, 15, ", 0x%x(r%d)", dst, get_dst (instr));
				if (ret == 2)
					ret = 4;
			}
		}
		break;
	default:
		ret = -1;
	}

	strncat (cmd->operands, dstbuf, MSP430_INSTR_MAXLEN - 1
			- strlen (cmd->operands));

	decode_emulation (instr, dst, cmd);

	return ret;
}

static int decode_twoop_opcode(ut16 instr, ut16 src, ut16 op2, struct msp430_cmd *cmd)
{
	int ret;
	ut8 opcode;

	opcode = get_twoop_opcode (instr);

	snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s", two_op_instrs[opcode]);
	if (get_bw(instr)) {
		strncat (cmd->instr, ".b", MSP430_INSTR_MAXLEN - 1 - strlen (cmd->instr));
	}
	ret = decode_addressing_mode (instr, src, op2, cmd);

	cmd->opcode = opcode;

	return ret;
}

static ut8 decode_addr(char *buf, ssize_t max, ut8 as, ut8 asd, ut8 reg, ut16 op, ut16 ext)
{
	char postfix = 0;
	int ret = 0;
	switch (asd) {
	case MSP430_ADDR_DIRECT:
		snprintf (buf, max, "r%d", reg);
		break;
	case MSP430_ADDR_INDEXED:
		// TODO: Probably broken sign
		snprintf (buf, max,
			  "0x%04x(r%d)", (ext << 16) | op, reg);
			  //"%c0x%04x(r%d)", (op ^ 0xffff) > 0 ? '+' : '-', op, reg);
		ret = 2;
		break;
	case MSP430_ADDR_INDIRECT_POST_INC:
		postfix = '+';
		// same same, fall through
	case MSP430_ADDR_INDIRECT:
		snprintf (buf, max, "@r%d%c", reg, postfix);
		break;
	case MSP430_ADDR_IMM:
		snprintf (buf, max, "#0x%04x", ext << 16 | op);
		ret = 2;
		break;
	// Special addressing
	case MSP430_ADDR_REPEAT:
		snprintf (buf, max, "#%d", ((reg >> 2) & 0xf) + 1);
		break;
	case MSP430_ADDR_REL:
		snprintf (buf, max, "0x%04x(r%d)", (ext << 16) | op, reg);
		ret = 2;
		break;
	case MSP430_ADDR_IMM20:
		snprintf (buf, max, "#0x%04x", (reg << 16) | op);
		ret = 2;
		break;
	case MSP430_ADDR_ABS20:
		snprintf (buf, max, "&0x%04x", (reg << 16) | op);
		ret = 2;
		break;
	case MSP430_ADDR_ABS:
		snprintf (buf, max, "&0x%04x", (ext << 16) | op);
		ret = 2;
		break;
	case MSP430_ADDR_CG1:
		snprintf (buf, max, "#%d", 4*(as - 1));
		break;
	case MSP430_ADDR_CG2:
		// TODO: FFh should be same size as instruction (ff, ffff, ffffff)
		snprintf (buf, max, "#%d", as == 3 ? 0xff : as);
		break;
	}
	return ret;
}

static ut8 get_jmp_opcode(ut16 instr)
{
	return instr >> 13;
}

static ut8 get_jmp_cond(ut16 instr)
{
	return (instr >> 10 ) & 7;
}

static ut8 output_430x(ut16 instr, ut16 ext, ut16 op1, ut16 op2, const opcode_table *op, struct msp430_cmd *cmd) {
	int ret = -1;
	ut8 as, asd;
	ut8 ad, add;
	ut8 src_ext = 0;
	ut8 dst_ext = 0;
	char postfix = 0;

	snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s%c",
		  op->name, ext ? 'x' : '\0');

	cmd->operands[0] = 0;

	if (op->as == MSP430_ADDR_AUTO) {
		as = get_as(instr);
		src_ext = (ext >> 7) & 0xf;
		dst_ext = get_dst(ext);
	} else {
		as = op->as;
	}

	if (as != MSP430_ADDR_NONE) {
		if (as > 1 && get_src(instr) == MSP430_SR)
			asd = MSP430_ADDR_CG1;
		else if (get_src(instr) == MSP430_R3)
			asd = MSP430_ADDR_CG2;
		else if (as && get_src(instr) == MSP430_SR)
			asd = MSP430_ADDR_ABS;
		else if (as == MSP430_ADDR_INDIRECT_POST_INC && get_src(instr) == MSP430_PC)
			asd = MSP430_ADDR_IMM;
		// TODO: Find another way to do this
		else if (as != MSP430_ADDR_REPEAT && as != MSP430_ADDR_ABS20 && get_src(instr) == MSP430_PC)
			asd = MSP430_ADDR_REL;
		else
			asd = as;
	} else {
		asd = as;
	}

	if (op->ad == MSP430_ADDR_AUTO) {
		ad = get_ad(instr);

		if (ad && get_dst(instr) == MSP430_SR)
			add = MSP430_ADDR_ABS;
		else
			add = ad;
	} else
		add = op-> ad;

	ret = 2;
	ret += decode_addr(cmd->operands, MSP430_INSTR_MAXLEN - 1,
			   as, asd,
			   get_src(instr), op1, src_ext);

	char dstbuf[16] = {0};

	ret += decode_addr(dstbuf, sizeof(dstbuf),
			   ad, add,
			   get_dst(instr), ret > 2 ? op2 : op1, dst_ext);
	// TODO: This should really not be done here, extension word compensation
	ret += ret > 2 ? 2 : 0;

	if (cmd->operands[0]) {
		strncat(cmd->operands, ", ", MSP430_INSTR_MAXLEN - 1
			- strlen (cmd->operands));
	}
	strncat (cmd->operands, dstbuf, MSP430_INSTR_MAXLEN - 1
		 - strlen (cmd->operands));
	return ret;
}

static ut8 output_jump(ut16 instr, ut16 ext, struct msp430_cmd *cmd)
{
	ut16 addr = instr & 0x3FF;
	cmd->jmp_addr = addr >= 0x300 ? (st16)((0xFE00 | addr) * 2 + 2) : (addr & 0x1FF) * 2 + 2;
	snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "$%c0x%04x", addr >= 0x300 ? '-' : '+',
		 addr >= 0x300 ? 0x400 - ((addr & 0x1FF) * 2 + 2) : (addr & 0x1FF) * 2 + 2);
	cmd->jmp_cond = get_jmp_cond (instr);
	cmd->opcode = get_jmp_opcode (instr);
	cmd->type = MSP430_JUMP;
	return 2;
}

static ut8 output_oneop(ut16 instr, ut16 ext, ut16 op1, struct msp430_cmd *cmd)
{
	ut8 asd = get_as(instr);
	ut8 reg = get_dst(instr);

	cmd->operands[0] = 0;

	if (get_dst(instr) == MSP430_SR)
		asd = MSP430_ADDR_ABS;

	ut8 ret = 2 + decode_addr(cmd->operands, MSP430_INSTR_MAXLEN - 1,
				  0, asd, reg, op1, get_dst(ext));
	return ret;
}

static ut8 decode_430x(ut16 instr, ut16 ext, ut16 op1, ut16 op2, struct msp430_cmd *cmd)
{
	// TODO: Use pointer instead of repeating array name
	for (int i = 0; oppocodo[i].name[0] != '\0'; i++) {
		if ((instr & oppocodo[i].mask) == oppocodo[i].id) {
			snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s%c",
				  oppocodo[i].name, ext ? 'x' : '\0');

			switch (oppocodo[i].ad) {
			case MSP430_ADDR_JUMP:
				return output_jump(instr, ext, cmd);

			case MSP430_ADDR_ONEOP:
				return output_oneop(instr, ext, op1, cmd);

			default:
				return output_430x(instr, ext, op1, op2, &oppocodo[i], cmd);
			}
		}
	}
	return -1;
}

static int decode_jmp (ut16 instr, struct msp430_cmd *cmd)
{
	ut16 addr;
	if (get_jmp_opcode(instr) != MSP430_JMP_OPC)
		return -1;

	snprintf(cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
			jmp_instrs[get_jmp_cond (instr)]);

	addr = instr & 0x3FF;

	cmd->jmp_addr = addr >= 0x300 ? (st16)((0xFE00 | addr) * 2 + 2) : (addr & 0x1FF) * 2 + 2;
	snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1,
			"$%c0x%04x", addr >= 0x300 ? '-' : '+',
			addr >= 0x300 ? 0x400 - ((addr & 0x1FF) * 2 + 2) : (addr & 0x1FF) * 2 + 2);

	cmd->jmp_cond = get_jmp_cond (instr);
	cmd->opcode = get_jmp_opcode (instr);
	cmd->type = MSP430_JUMP;

	return 2;
}

static ut8 get_inst_id(ut16 instr)
{
	return (instr >> 8) & 0x3;
}

static int get_oneop_opcode(ut16 instr)
{
	return (instr >> 7) & 0x7;
}

static int decode_oneop_opcode(ut16 instr, ut16 op, struct msp430_cmd *cmd)
{
	int ret = 2;
	ut8 ad, opcode;

	if ((instr >> 10) != 4)
		return -1;

	opcode = get_oneop_opcode (instr);

	ad = get_as (instr);

	snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s",
			one_op_instrs[opcode]);

	cmd->opcode = opcode;

	switch (opcode) {
	case MSP430_RCR:
	case MSP430_SWPB:
	case MSP430_RRA:
	case MSP430_SXT:
	case MSP430_PUSH:
	case MSP430_CALL:
		switch (ad) {
		case 0:
			switch (get_dst (instr)) {
			case MSP430_R3:
				snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#0");
				break;
			default:
				snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"r%d", get_dst (instr));
			}
			ret = 2;
			break;
		case 1:
			switch (get_dst (instr)) {
			case MSP430_PC:
				snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"0x%04x", op);
				break;
			case MSP430_SR:
				snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"&0x%04x", op);
				break;
			default:
				snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"0x%x(r%d)", op, get_dst (instr));
			}

			ret = 4;
			break;
		case 2:
			switch (get_dst (instr)) {
			case MSP430_SR:
				snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#4");
				break;
			case MSP430_R3:
				snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "#2");
				break;
			default:
				snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
						"@r%d", get_dst(instr));
			}

			ret = 2;
			break;
		case 3:
			snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1,
					"#0x%04x", op);
			ret = 4;
			break;
		default:
			ret = -1;
		}
		break;
	case MSP430_RETI:
		cmd->operands[0] = '\0';
		break;
	}

	cmd->type = MSP430_ONEOP;

	return ret;
}

int msp430x_decode_command(const ut8 *in, struct msp430_cmd *cmd)
{
	int ret = -1;
	ut16 instr;
	ut16 ext = 0;
	ut16 operand1, operand2;
	ut8 opcode;

	r_mem_copyendian((ut8*)&instr, in, sizeof (ut16), LIL_ENDIAN);

	if (is_ext_word(instr)) {
		in += 2;
		ext = instr;
		r_mem_copyendian((ut8*)&instr, in, sizeof (ut16), LIL_ENDIAN);
	}

	r_mem_copyendian((ut8*)&operand1, in + 2, sizeof (ut16), LIL_ENDIAN);
	r_mem_copyendian((ut8*)&operand2, in + 4, sizeof (ut16), LIL_ENDIAN);
	ret = decode_430x(instr, ext, operand1, operand2, cmd);
	return ret;//+ ext ? 2 : 0;
}
