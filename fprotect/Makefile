CONFIG_MODULE_SIG=n

obj-m += fprotect.o

PWD := $(CURDIR)/build

all:
	mkdir -p build
	cp $(CURDIR)/Makefile $(CURDIR)/build/.
	cp $(CURDIR)/fprotect.c $(CURDIR)/build/.
	cp $(CURDIR)/queue.h $(CURDIR)/build/.
	cp $(CURDIR)/hashtab.h $(CURDIR)/build/.
	cp $(CURDIR)/str.h $(CURDIR)/build/.
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
