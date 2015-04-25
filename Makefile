ccflags-y := -std=gnu99 -Wno-declaration-after-statement -g -D__DEBUG

obj-m += ipea_module.o
ipea_module-objs := ipea.o utility.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
 
help:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) help 

%.in: %.ko
	sudo insmod $<

%.rm: %.ko
	sudo rmmod $<
