# Build inside a Linux machine with the kernel headers installed:
#   make && insmod aod_linux.ko
obj-m := aod_linux.o
ccflags-y := -I$(src)/../common
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
