# Makefile for W1 VHF/UHF Anti-Stealth Radar Ring-0 Driver
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c .*.cmd Module.symvers modules.order
