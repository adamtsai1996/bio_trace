# kernel root directory
KERNEL_DIR=/home/adam/working/shamu

MODULE_NAME=bio_trace

obj-m := ${MODULE_NAME}.o

${MODULE_NAME}-objs := trace_main.o common.o  sha1.o

PWD := $(shell pwd)

ARCH=arm
SUBARCH=arm
# cross_compiler directory
CROSS_COMPILE=/home/adam/working/cross_compiler/bin/arm-eabi-
#CROSS_COMPILE=/home/claude/nexus6/arm-linux-androideabi-4.6/bin/arm-linux-androideabi-
EXTRA_CFLAGS=-fno-pic

CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld

OBJDUMP=arm-linux-gnueabihf-objdump

all:
	make -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) modules
	$(OBJDUMP)  -D -S --show-raw-insn --prefix-addresses --line-number $(MODULE_NAME).ko >objdump
clean:
	make -C $(KERNEL_DIR) M=$(pwd) clean
	rm -rf *.o .*.cmd *.cmd *.ko *.mod.c .tmp_versions *.order *.symvers objdump

