KDIR   := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

# Core module
obj-m += nf_antidos.o
nf_antidos-y := core/nf_antidos.o

# Plugin modules (load sau core)
obj-m += tb_plugin.o
obj-m += lb_plugin.o
obj-m += fw_plugin.o

tb_plugin-y := plugins/tb_plugin.o
lb_plugin-y := plugins/lb_plugin.o
fw_plugin-y := plugins/fw_plugin.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# ── Load / unload ──────────────────────────────────────────────────────────
load:
	sudo insmod nf_antidos.ko
	sudo insmod tb_plugin.ko
	sudo insmod lb_plugin.ko
	sudo insmod fw_plugin.ko
	@echo "Loaded. Active plugin:"
	@cat /proc/nf_antidos/plugin

unload:
	-sudo rmmod fw_plugin
	-sudo rmmod lb_plugin
	-sudo rmmod tb_plugin
	sudo rmmod nf_antidos

# ── Đổi plugin runtime ─────────────────────────────────────────────────────
use-tb:
	echo "token_bucket" | sudo tee /proc/nf_antidos/plugin

use-lb:
	echo "leaky_bucket" | sudo tee /proc/nf_antidos/plugin

use-fw:
	echo "fixed_window" | sudo tee /proc/nf_antidos/plugin

# ── Quan sát ───────────────────────────────────────────────────────────────
stats:
	cat /proc/nf_antidos/stats

banned:
	cat /proc/nf_antidos/banned

plugin:
	cat /proc/nf_antidos/plugin

log:
	dmesg | grep nf_antidos | tail -20

.PHONY: all clean load unload use-tb use-lb use-fw stats banned plugin log