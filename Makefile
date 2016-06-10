ccflags-y := -std=gnu99 -Wno-declaration-after-statement -g -D__DEBUG

obj-m := ipea_module.o
ipea_module-objs := ipea.o utility.o

# The directory where the kernel source is located.
KDIR := /lib/modules/`uname -r`/build

all:
	make -C $(KDIR) M=$(PWD) modules

install:
	make -C $(KDIR) M=$(PWD) modules_install

clean:
	make -C $(KDIR) M=$(PWD) clean
 
help:
	make -C $(KDIR) M=$(PWD) help 
