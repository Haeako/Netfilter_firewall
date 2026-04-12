KDIR   := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

# Core module
obj-m += nf_antidos.o
nf_antidos-y := src/core/nf_antidos.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
