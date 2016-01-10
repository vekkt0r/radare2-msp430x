NAME=msp430x
R2_PLUGIN_PATH=$(shell r2 -hh|grep LIBR_PLUGINS|awk '{print $$2}')
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm r_anal)
LDFLAGS=-shared $(shell pkg-config --libs r_asm r_anal)
OBJS=$(NAME)_disas.o opcodes.o
OBJS_ASM=asm_$(NAME).o $(OBJS)
OBJS_ANAL=anal_$(NAME).o $(OBJS)
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB_ASM=asm_$(NAME).$(SO_EXT)
LIB_ANAL=anal_$(NAME).$(SO_EXT)
DEPS= $(OBJS_ASM:.o=.d) $(OBJS_ANAL:.o=.d)

all: $(LIB_ASM) $(LIB_ANAL)

clean:
	rm -f $(LIB_ASM) $(LIB_ANAL) $(OBJS_ASM) $(OBJS_ANAL) $(DEPS)

-include $(DEPS)

%.o: %.c
	$(CC) -c $(CFLAGS) -MMD -o $@ $<

$(LIB_ASM): $(OBJS_ASM)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $(LIB_ASM)

$(LIB_ANAL): $(OBJS_ANAL)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $(LIB_ANAL)

install:
	cp -f $(LIB_ANAL) $(R2_PLUGIN_PATH)
	cp -f $(LIB_ASM) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/$(LIB_ANAL)
	rm -f $(R2_PLUGIN_PATH)/$(LIB_ASM)
