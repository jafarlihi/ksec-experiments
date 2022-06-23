CONFIG_MODULE_SIG=n

obj-m += hello.o

PWD := $(CURDIR)/build

all:
	mkdir -p build
	cp $(CURDIR)/Makefile $(CURDIR)/build/.
	cp $(CURDIR)/hello.c $(CURDIR)/build/.
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
