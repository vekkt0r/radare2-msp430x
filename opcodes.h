#ifndef OPCODES_H
#define OPCODES_H

#include <r_types.h>
#include <r_util.h>

typedef struct {
	char name[8];
	ut16 id;
	ut16 mask;
	ut8 as;
	ut8 ad;
	ut8 type;
} opcode_table;

const opcode_table* opcode_find(ut16 instruction);

#endif /* OPCODES_H */
