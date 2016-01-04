#include <r_types.h>
#include <r_util.h>

#include "msp430x_disas.h"

/* Known "issues":
   - mov #0, offset(reg) is shown as clr offset(reg) instead of mov
 */

typedef struct  {
	char name[8];
	ut16 id;
	ut16 mask;
	ut8  as;
	ut8  ad;
	ut8  type;
} opcode_table;

static const opcode_table opcodes[] = {

	// Emulated instructions
	{"nop",    0x4303, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"ret",    0x4130, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"adc",    0x6300, 0xff30, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"br",     0x4000, 0xf08f, MSP430_ADDR_AUTO,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"clr",    0x4300, 0xff30, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"clrc",   0xc312, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"clrn",   0xc222, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"clrz",   0xc322, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"dadc",   0xa300, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"dec",    0x8310, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"decd",   0x8320, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"dint",   0xc232, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"eint",   0xd232, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"inc",    0x5310, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"incd",   0x5320, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"pop",    0x4130, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"rla",    0x5500, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"rlc",    0x6500, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"sbc",    0x7300, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"setc",   0xd312, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"setn",   0xd222, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"setz",   0xd322, 0xffff, MSP430_ADDR_NONE,    MSP430_ADDR_NONE, MSP430_TWOOP},
	{"tst",    0x9300, 0xfff0, MSP430_ADDR_NONE,    MSP430_ADDR_AUTO, MSP430_TWOOP},

	// Two operand extended instructions
	{"mova",   0x0000, 0xf0f0, MSP430_ADDR_INDIRECT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"mova",   0x0010, 0xf0f0, MSP430_ADDR_INDIRECT_POST_INC, MSP430_ADDR_DIRECT, MSP430_X},
	{"mova",   0x0020, 0xf0f0, MSP430_ADDR_ABS20,    MSP430_ADDR_DIRECT, MSP430_X},
	{"mova",   0x0030, 0xf0f0, MSP430_ADDR_INDEXED,  MSP430_ADDR_DIRECT, MSP430_X},
	{"mova",   0x0060, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_ABS20, MSP430_X},
	{"mova",   0x0070, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_INDEXED, MSP430_X},
	{"mova",   0x0080, 0xf0f0, MSP430_ADDR_IMM20,    MSP430_ADDR_DIRECT, MSP430_X},
	{"cmpa",   0x0090, 0xf0f0, MSP430_ADDR_IMM20,    MSP430_ADDR_DIRECT, MSP430_X},
	{"adda",   0x00a0, 0xf0f0, MSP430_ADDR_IMM20,    MSP430_ADDR_DIRECT, MSP430_X},
	{"suba",   0x00b0, 0xf0f0, MSP430_ADDR_IMM20,    MSP430_ADDR_DIRECT, MSP430_X},
	{"mova",   0x00c0, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"cmpa",   0x00d0, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"adda",   0x00e0, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"suba",   0x00f0, 0xf0f0, MSP430_ADDR_DIRECT,   MSP430_ADDR_DIRECT, MSP430_X},

	// One operand extended instructions
	{"rrcm.a", 0x0040, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"rram.a", 0x0140, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"rlam.a", 0x0240, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"rrum.a", 0x0340, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"rrcm",   0x0050, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"rram",   0x0150, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"rlam",   0x0250, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT, MSP430_X},
	{"rrum",   0x0350, 0xf3f0, MSP430_ADDR_REPEAT,   MSP430_ADDR_DIRECT, MSP430_X},

	// Third table extended
	{"calla",   0x1340, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_DIRECT, MSP430_X},
	{"calla",   0x1350, 0xfff0, MSP430_ADDR_NONE, MSP430_ADDR_INDEXED, MSP430_X},
	{"pushm.a", 0x1400, 0xff00, MSP430_ADDR_PP,   MSP430_ADDR_DIRECT, MSP430_X},
	{"pushm",   0x1500, 0xff00, MSP430_ADDR_PP ,  MSP430_ADDR_DIRECT, MSP430_X},
	{"popm.a",  0x1600, 0xff00, MSP430_ADDR_PP,   MSP430_ADDR_POPM, MSP430_X},
	{"popm",    0x1700, 0xff00, MSP430_ADDR_PP,   MSP430_ADDR_POPM, MSP430_X},

	// Two operand instructions
	{"mov",   0x4000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"add",   0x5000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"addc",  0x6000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"subc",  0x7000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"sub",   0x8000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"cmp",   0x9000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"dadd",  0xa000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"bit",   0xb000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"bic",   0xc000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"bis",   0xd000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"xor",   0xe000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},
	{"and",   0xf000, 0xf000, MSP430_ADDR_AUTO, MSP430_ADDR_AUTO, MSP430_TWOOP},

	// Jumps
	{"jnz",   0x2000, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP, MSP430_JUMP},
	{"jz",    0x2400, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP, MSP430_JUMP},
	{"jnc",   0x2800, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP, MSP430_JUMP},
	{"jc",    0x2c00, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP, MSP430_JUMP},
	{"jn",    0x3000, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP, MSP430_JUMP},
	{"jge",   0x3400, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP, MSP430_JUMP},
	{"jl",    0x3800, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP, MSP430_JUMP},
	{"jmp",   0x3c00, 0xfc00, MSP430_ADDR_NONE,  MSP430_ADDR_JUMP, MSP430_JUMP},

	// One operand instructions
	{"rrc",   0x1000, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP, MSP430_ONEOP},
	{"swpb",  0x1080, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP, MSP430_ONEOP},
	{"rra",   0x1100, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP, MSP430_ONEOP},
	{"sxt",   0x1180, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP, MSP430_ONEOP},
	{"push",  0x1200, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP, MSP430_ONEOP},
	{"call",  0x1280, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_ONEOP, MSP430_ONEOP},
	{"reti",  0x1300, 0xf380, MSP430_ADDR_NONE,  MSP430_ADDR_NONE, MSP430_ONEOP},

	// Do not remove
	{},
};

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

// TODO: Unused
static ut8 get_bw(ut16 instr)
{
	return (instr >> 6) & 1;
}

static ut8 get_ad(ut16 instr)
{
	return (instr >> 7) & 1;
}

static ut8 is_extension_word(ut16 instr)
{
	return ((instr >> 11) & 0x1f) == 3;
}

static ut8 decode_addr(char *buf, ssize_t max, ut8 konst, ut8 mode, ut8 reg, ut16 op, ut16 ext, st32 *jmp_addr)
{
	char postfix = 0;
	int ret = 0;
	st32 jmp = 0;
	switch (mode) {
	case MSP430_ADDR_DIRECT:
		snprintf (buf, max, "r%d", reg);
		ret = 0;
		break;
	case MSP430_ADDR_INDEXED:
		// TODO: Probably broken sign
		snprintf (buf, max, "0x%04x(r%d)", (ext << 16) | op, reg);
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
		jmp = ext << 16 | op;
		snprintf (buf, max, "#0x%04x", jmp);
		ret = 2;
		break;
	case MSP430_ADDR_REPEAT:
		snprintf (buf, max, "#%d", ((reg >> 2) & 0xf) + 1);
		break;
	case MSP430_ADDR_PP:
		snprintf (buf, max, "#%d", op);
		break;
	case MSP430_ADDR_POPM:
		snprintf (buf, max, "r%d", op);
		break;
	case MSP430_ADDR_REL:
		snprintf (buf, max, "0x%04x(r%d)", (ext << 16) | op, reg);
		ret = 2;
		break;
	case MSP430_ADDR_IMM20:
		jmp = (reg << 16) | op;
		snprintf (buf, max, "#0x%04x", jmp);
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
		snprintf (buf, max, "#%d", 4*(konst - 1));
		break;
	case MSP430_ADDR_CG2:
		// TODO: FFh should be same size as instruction (ff, ffff, ffffff)
		snprintf (buf, max, "#%d", konst == 3 ? 0xff : konst);
		break;
	default:
		buf[0] = '\0';
		break;
	}
	*jmp_addr = jmp;
	return ret;
}

static ut8 decode_addr_mode(ut8 mode, ut8 dst)
{
	ut8 dec;
	if (mode > 1 && dst == MSP430_SR)
		dec = MSP430_ADDR_CG1;
	else if (dst == MSP430_R3)
		dec = MSP430_ADDR_CG2;
	else if (mode && dst == MSP430_SR)
		dec = MSP430_ADDR_ABS;
	else if (mode == MSP430_ADDR_INDIRECT_POST_INC && dst == MSP430_PC)
		dec = MSP430_ADDR_IMM;
	// TODO: Find another way to do this
	else if (mode != MSP430_ADDR_REPEAT && mode != MSP430_ADDR_ABS20 && dst == MSP430_PC)
		dec = MSP430_ADDR_REL;
	else
		dec = mode;

	return dec;
}

static ut8 output_twoop(ut16 instr, ut16 ext, ut16 op1, ut16 op2, const opcode_table *op, struct msp430_cmd *cmd) {
	int ret;
	ut8 as, asd;
	ut8 ad, add;
	ut8 src_ext = 0;
	ut8 dst_ext = 0;
	char postfix = 0;

	snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s%s%s",
		  op->name, ext ? "x" : "",
		  get_bw(instr) && op->type != MSP430_X ? ".b" : "");

	if (op->as == MSP430_ADDR_AUTO) {
		as = get_as(instr);
		src_ext = (ext >> 7) & 0xf;
	} else {
		as = op->as;
	}

	// TODO: One more hack..
	if (as == MSP430_ADDR_PP) {
		asd = as;
		op1 = ((instr >> 4) & 0xf) + 1;
	}
	else if (as != MSP430_ADDR_NONE) {
		asd = decode_addr_mode(as, get_src(instr));
	} else {
		asd = as;
	}

	if (op->ad == MSP430_ADDR_AUTO) {
		ad = get_ad(instr);

		if (ad && get_dst(instr) == MSP430_SR)
			add = MSP430_ADDR_ABS;
		else
			add = ad;
		dst_ext = get_dst(ext);
	} else if (op->ad == MSP430_ADDR_POPM) {
		add = MSP430_ADDR_POPM;
		op1 = get_dst(instr) + (instr >> 4)&0xf;
	} else
		add = op-> ad;

	ret = decode_addr(cmd->operands, MSP430_INSTR_MAXLEN - 1,
			  as, asd,
			  get_src(instr), op1, src_ext,
			  &cmd->jmp_addr);

	char dstbuf[16] = {0};

	ret += decode_addr(dstbuf, sizeof(dstbuf),
			   ad, add,
			   get_dst(instr), ret > 0 ? op2 : op1, dst_ext,
			   &cmd->jmp_addr);

	if (cmd->operands[0] && dstbuf[0]) {
		strncat(cmd->operands, ", ", MSP430_INSTR_MAXLEN - 1
			- strlen (cmd->operands));
	}
	strncat (cmd->operands, dstbuf, MSP430_INSTR_MAXLEN - 1
		 - strlen (cmd->operands));
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

static ut8 output_jump(ut16 instr, ut16 ext, struct msp430_cmd *cmd)
{
	ut16 addr = instr & 0x3FF;
	cmd->jmp_addr = (st16)(addr >= 0x300 ? (st16)((0xFE00 | addr) * 2 + 2) : (addr & 0x1FF) * 2 + 2);
	snprintf(cmd->operands, MSP430_INSTR_MAXLEN - 1, "$%c0x%04x", addr >= 0x300 ? '-' : '+',
		 addr >= 0x300 ? 0x400 - ((addr & 0x1FF) * 2 + 2) : (addr & 0x1FF) * 2 + 2);
	cmd->jmp_cond = get_jmp_cond (instr);
	cmd->opcode = get_jmp_opcode (instr);
	cmd->type = MSP430_JUMP;
	return 0;
}

static ut8 output_oneop(ut16 instr, ut16 ext, ut16 op1, struct msp430_cmd *cmd)
{
	ut8 as = get_as(instr);
	ut8 reg = get_dst(instr);
	ut8 mode = decode_addr_mode(as, reg);
	return decode_addr(cmd->operands, MSP430_INSTR_MAXLEN - 1,
			   as, mode, reg, op1, get_dst(ext), &cmd->jmp_addr);
}

static ut8 decode_430x(ut16 instr, ut16 op1, ut16 op2, ut16 ext, struct msp430_cmd *cmd)
{
	for (const opcode_table *ot = opcodes; ot->name[0] != '\0'; ot++) {
		if ((instr & ot->mask) == ot->id) {
			snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s%c",
				  ot->name, ext ? 'x' : '\0');

			switch (ot->ad) {
			case MSP430_ADDR_JUMP:
				return 2 + output_jump(instr, ext, cmd);

			case MSP430_ADDR_ONEOP:
				return 2 + output_oneop(instr, ext, op1, cmd);

			default:
				return 2 + output_twoop(instr, ext, op1, op2, ot, cmd);
			}
		}
	}
	return -1;
}

int msp430x_decode_command(const ut8 *in, struct msp430_cmd *cmd)
{
	int ret = -1;
	ut16 instr;
	ut16 extension = 0;
	ut16 operand1, operand2;
	ut8 opcode;

	r_mem_copyendian((ut8*)&instr, in, sizeof (ut16), LIL_ENDIAN);

	if (is_extension_word(instr)) {
		in += 2;
		extension = instr;
		r_mem_copyendian((ut8*)&instr, in, sizeof (ut16), LIL_ENDIAN);
	}

	r_mem_copyendian((ut8*)&operand1, in + 2, sizeof (ut16), LIL_ENDIAN);
	r_mem_copyendian((ut8*)&operand2, in + 4, sizeof (ut16), LIL_ENDIAN);
	ret = decode_430x(instr, operand1, operand2, extension, cmd);
	ret += extension ? 2 : 0;
	return ret;
}
