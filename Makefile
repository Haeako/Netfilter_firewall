KDIR   := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

# Core module
obj-m += nf_antidos.o
nf_antidos-y := src/core/nf_antidos.o

# Plugin modules (load sau core)
obj-m += fixed_window.o
obj-m += token_bucket.o

fixed_window-y := src/plugins/fixed_window.o
token_bucket-y := src/plugins/token_bucket.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
