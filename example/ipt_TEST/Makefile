# @Author: JanKinCai
# @Date:   2020-11-23 15:24:14
# @Last Modified by:   jankincai
# @Last Modified time: 2021-03-18 10:02:22
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
obj-m += ipt_TEST.o

all: ipt_TEST.h ipt_TEST.c
	make -C ${KERNEL_DIR} M=$$PWD;
	make libipt_TEST.so
install: libipt_TEST.so ipt_TEST.ko
	sudo apt-mark hold linux-image-generic linux-headers-generic
	cp ./libipt_TEST.so /usr/lib/x86_64-linux-gnu/xtables
	cp ./ipt_TEST.ko /lib/modules/`uname -r`/kernel/net/netfilter/
	depmod -a

	sudo modprobe -i ipt_TEST
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
libipt_TEST.so: libipt_TEST.o
	gcc -shared -fPIC -o $@ $^;
libipt_TEST.o: libipt_TEST.c
	gcc -O2 -Wall -D_INIT=lib$*_init -fPIC -c -o $@ $<;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -rf libipt_TEST.so libipt_TEST.o
uninstall:
	rmmod ipt_TEST
	rm /usr/lib/x86_64-linux-gnu/xtables/libipt_TEST.so
	rm /lib/modules/`uname -r`/kernel/net/netfilter/ipt_TEST.ko
