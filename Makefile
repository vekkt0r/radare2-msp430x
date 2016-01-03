NAME=msp430x
R2_PLUGIN_PATH=$(shell r2 -hh|grep LIBR_PLUGINS|awk '{print $$2}')
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm r_anal)
LDFLAGS=-shared $(shell pkg-config --libs r_asm r_anal)
OBJS_ASM=asm_$(NAME).o $(NAME)_disas.o
OBJS_ANAL=anal_$(NAME).o $(NAME)_disas.o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB_ASM=asm_$(NAME).$(SO_EXT)
LIB_ANAL=anal_$(NAME).$(SO_EXT)

all: $(LIB_ASM) $(LIB_ANAL)

clean:
	rm -f $(LIB_ASM) $(LIB_ANAL) $(OBJS_ASM) $(OBJS_ANAL)

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
# DO NOT DELETE

anal_msp430x.o: /usr/include/string.h /usr/include/_types.h
anal_msp430x.o: /usr/include/sys/_types.h /usr/include/sys/cdefs.h
anal_msp430x.o: /usr/include/sys/_symbol_aliasing.h
anal_msp430x.o: /usr/include/sys/_posix_availability.h
anal_msp430x.o: /usr/include/machine/_types.h /usr/include/i386/_types.h
anal_msp430x.o: /usr/include/sys/_pthread/_pthread_types.h
anal_msp430x.o: /usr/include/Availability.h
anal_msp430x.o: /usr/include/AvailabilityInternal.h
anal_msp430x.o: /usr/include/sys/_types/_size_t.h
anal_msp430x.o: /usr/include/sys/_types/_null.h
anal_msp430x.o: /usr/include/sys/_types/_rsize_t.h
anal_msp430x.o: /usr/include/sys/_types/_errno_t.h
anal_msp430x.o: /usr/include/sys/_types/_ssize_t.h /usr/include/strings.h
anal_msp430x.o: /usr/include/secure/_string.h /usr/include/secure/_common.h
anal_msp430x.o: msp430x_disas.h
