CONFIG_MODULE_SIG=n

obj-m += ksec.o

PWD := $(CURDIR)/build

all:
	mkdir -p build
	cp $(CURDIR)/Makefile $(CURDIR)/build/.
	cp $(CURDIR)/ksec.c $(CURDIR)/build/.
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -rf build
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
