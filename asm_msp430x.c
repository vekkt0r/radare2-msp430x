#include <stdio.h>
#include <string.h>
//#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "msp430x_disas.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	int ret;
	struct msp430_cmd cmd = {0};

	ret = msp430x_decode_command (buf, &cmd);

	if (ret > 0) {
	    if (cmd.prefix[0]) {
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %s %s", cmd.prefix, cmd.instr, cmd.operands);
	    }
	    else if (cmd.operands[0]) {
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %s", cmd.instr, cmd.operands);
	    } else {
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s", cmd.instr);
	    }
	}

	op->size = ret;

	return ret;
}

RAsmPlugin r_asm_plugin_msp430x = {
	.name = "msp430xx",
	.license = "LGPL3",
	.desc = "msp430x disassembly plugin",
	.arch = "msp430x",
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_msp430x,
};
#endif
