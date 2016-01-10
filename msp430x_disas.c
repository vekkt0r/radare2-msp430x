#include <r_types.h>
#include <r_util.h>

#include "msp430x_disas.h"

/* Known "issues":
   - mov #0, offset(reg) is shown as clr offset(reg) instead of mov
 */

static int get_src (instr) {
	return (instr >> 8) & 0xF;
}

static int get_dst (instr) {
	return instr & 0xF;
}

static ut8 get_as (ut16 instr) {
	return (instr >> 4) & 3;
}

static ut8 get_bw (ut16 instr) {
	return (instr >> 6) & 1;
}

static ut8 get_ad (ut16 instr) {
	return (instr >> 7) & 1;
}

static ut8 is_extension_word (ut16 instr) {
	return ((instr >> 11) & 0x1f) == 3;
}

static ut8 decode_addr (char *buf, ssize_t max, ut8 as, ut8 mode, ut8 reg, ut16 op, ut16 ext, st32 *addr) {
	char postfix = 0;
	int ret = 0;
	st32 address = 0;
	switch (mode) {
	case MSP430_ADDR_DIRECT:
		snprintf (buf, max, "r%d", reg);
		ret = 0;
		break;
	case MSP430_ADDR_INDEXED:
		// Do not print out sign, just raw hex
		snprintf (buf, max, "0x%04x(r%d)", (ext << 16) | op, reg);
		ret = 2;
		break;
	case MSP430_ADDR_INDIRECT_POST_INC:
		postfix = '+';
	// same same, fall through
	case MSP430_ADDR_INDIRECT:
		snprintf (buf, max, "@r%d%c", reg, postfix);
		break;
	case MSP430_ADDR_IMM:
		address = ext << 16 | op;
		snprintf (buf, max, "#0x%04x", address);
		ret = 2;
		break;
	case MSP430_ADDR_REPEAT:
		snprintf (buf, max, "#%d", ((reg >> 2) & 0xf) + 1);
		break;
	case MSP430_ADDR_PUSHPOP:
		snprintf (buf, max, "#%d", op);
		break;
	case MSP430_ADDR_POPM:
		snprintf (buf, max, "r%d", op);
		break;
	case MSP430_ADDR_IMM20:
		address = (reg << 16) | op;
		snprintf (buf, max, "#0x%05x", address);
		ret = 2;
		break;
	case MSP430_ADDR_ABS20:
		address = (reg << 16) | op;
		snprintf (buf, max, "&0x%04x", address);
		ret = 2;
		break;
	case MSP430_ADDR_ABS:
		address = (ext << 16) | op;
		snprintf (buf, max, "&0x%04x", address);
		ret = 2;
		break;
	case MSP430_ADDR_CG1:
		snprintf (buf, max, "#%d", 4 * (as - 1));
		break;
	case MSP430_ADDR_CG2:
		snprintf (buf, max, "#%d", as == 3 ? -1 : as);
		break;
	default:
		buf[0] = '\0';
		break;
	}
	*addr = address;
	return ret;
}

static ut8 decode_addr_mode (ut8 mode, ut8 dst) {
	if (mode > 1 && dst == MSP430_SR)
		return MSP430_ADDR_CG1;
	else if (dst == MSP430_R3)
		return MSP430_ADDR_CG2;
	else if (mode && dst == MSP430_SR)
		return MSP430_ADDR_ABS;
	else if (mode == MSP430_ADDR_INDIRECT_POST_INC
		 && dst == MSP430_PC)
		return MSP430_ADDR_IMM;
	else
		return mode;
}

static ut8 output_twoop (ut16 instr,
			 ut16 ext,
			 ut16 op1,
			 ut16 op2,
			 const opcode_table *op,
			 struct msp430_cmd *cmd) {
	int ret;
	ut8 as, src_mode;
	ut8 ad = MSP430_ADDR_NONE, dst_mode;
	ut8 src_ext = 0;
	ut8 dst_ext = 0;
	st32 data_ptr;

	snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s%s%s",
		  op->name,
		  ext ? "x" : "",
		  get_bw (instr) && op->type != MSP430_X ? ".b" : "");

	if (op->as == MSP430_ADDR_AUTO) {
		as = get_as (instr);
		src_ext = (ext >> 7) & 0xf;
	} else {
		as = op->as;
	}

	// Push/pop have their very own encoding of as / op
	if (as == MSP430_ADDR_PUSHPOP) {
		src_mode = as;
		op1 = ((instr >> 4) & 0xf) + 1;
	} else if (as != MSP430_ADDR_NONE) {
		src_mode = decode_addr_mode (as, get_src (instr));
	} else {
		src_mode = as;
	}

	if (op->ad == MSP430_ADDR_AUTO) {
		ad = get_ad (instr);

		if (ad && get_dst (instr) == MSP430_SR)
			dst_mode = MSP430_ADDR_ABS;
		else
			dst_mode = ad;
		dst_ext = get_dst (ext);
	} else if (op->ad == MSP430_ADDR_POPM) {
		dst_mode = MSP430_ADDR_POPM;
		op1 = get_dst (instr) + (instr >> 4) & 0xf;
	} else {
		dst_mode = op->ad;
	}
	ret = decode_addr (cmd->operands, MSP430_INSTR_MAXLEN - 1,
			   as, src_mode,
			   get_src (instr), op1, src_ext,
			   &data_ptr);

	char dstbuf[16] = {0};

	if (data_ptr != 0) {
		cmd->ptr_addr = data_ptr;
	}

	ret += decode_addr (dstbuf, sizeof(dstbuf),
			    ad, dst_mode,
			    get_dst (instr), ret > 0 ? op2 : op1, dst_ext,
			    &data_ptr);

	if (data_ptr != 0) {
		if (op->radare_type == R_ANAL_OP_TYPE_CALL) {
			cmd->jmp_addr = data_ptr;
		} else {
			cmd->ptr_addr = data_ptr;
		}
	}

	if (cmd->operands[0] && dstbuf[0]) {
		strncat (cmd->operands, ", ", MSP430_INSTR_MAXLEN - 1 - strlen (cmd->operands));
	}
	strncat (cmd->operands, dstbuf, MSP430_INSTR_MAXLEN - 1 - strlen (cmd->operands));
	return ret;
}

static ut8 get_jmp_opcode (ut16 instr) {
	return instr >> 13;
}

static ut8 get_jmp_cond (ut16 instr) {
	return (instr >> 10) & 7;
}

static ut8 output_jump (ut16 instr, struct msp430_cmd *cmd) {
	ut16 addr = instr & 0x3FF;
	cmd->jmp_addr = (st16)(addr >= 0x300 ? (st16)((0xFE00 | addr) * 2 + 2) : (addr & 0x1FF) * 2 + 2);
	snprintf (cmd->operands, MSP430_INSTR_MAXLEN - 1, "$%c0x%04x", addr >= 0x300 ? '-' : '+',
		  addr >= 0x300 ? 0x400 - ((addr & 0x1FF) * 2 + 2) : (addr & 0x1FF) * 2 + 2);
	cmd->jmp_cond = get_jmp_cond (instr);
	cmd->opcode = get_jmp_opcode (instr);
	cmd->type = MSP430_JUMP;
	return 0;
}

static ut8 output_oneop (ut16 instr, ut16 ext, ut16 op1, struct msp430_cmd *cmd) {
	ut8 as = get_as (instr);
	ut8 reg = get_dst (instr);
	ut8 mode = decode_addr_mode (as, reg);
	return decode_addr (cmd->operands, MSP430_INSTR_MAXLEN - 1,
			    as, mode, reg, op1, get_dst (ext), &cmd->jmp_addr);
}

static void output_prefix(ut8 len, ut16 ext, char *prefix) {
	// Check if we have a repeat count
	if (len == 2 && ((ext & 0xf) != 0)) {
		if (ext & 0x80) {
			snprintf (prefix, MSP430_INSTR_MAXLEN, ".rpt r%d", ext & 0x0f);
		} else {
			snprintf (prefix, MSP430_INSTR_MAXLEN, ".rpt #%d", 1 + (ext & 0x0f));
		}
	}
}

static ut8 decode_430x (ut16 instr, ut16 op1, ut16 op2, ut16 ext, struct msp430_cmd *cmd) {
	const opcode_table *ot = opcode_find(instr);
	ut8 len = 0;
	if (ot) {
		snprintf (cmd->instr, MSP430_INSTR_MAXLEN - 1, "%s%c",
			  ot->name, ext ? 'x' : '\0');

		switch (ot->ad) {
		case MSP430_ADDR_JUMP:
			len = 2 + output_jump (instr, cmd);
			break;

		case MSP430_ADDR_ONEOP:
			len = 2 + output_oneop (instr, ext, op1, cmd);
			break;

		default:
			len = 2 + output_twoop (instr, ext, op1, op2, ot, cmd);
			break;
		}
		cmd->op = ot;
		output_prefix(len, ext, cmd->prefix);
		return len;
	}
	return -1;
}

int msp430x_decode_command (const ut8 *in, struct msp430_cmd *cmd) {
	int ret = -1;
	ut16 instr;
	ut16 extension = 0;
	ut16 operand1, operand2;

	r_mem_copyendian ((ut8 *)&instr, in, sizeof(ut16), LIL_ENDIAN);

	if (is_extension_word (instr)) {
		in += 2;
		extension = instr;
		r_mem_copyendian ((ut8 *)&instr, in, sizeof(ut16), LIL_ENDIAN);
	}

	r_mem_copyendian ((ut8 *)&operand1, in + 2, sizeof(ut16), LIL_ENDIAN);
	r_mem_copyendian ((ut8 *)&operand2, in + 4, sizeof(ut16), LIL_ENDIAN);
	ret = decode_430x (instr, operand1, operand2, extension, cmd);
	ret += extension ? 2 : 0;
	return ret;
}
