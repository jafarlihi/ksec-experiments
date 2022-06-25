#include <linux/module.h>
#include <linux/types.h>

typedef struct {
    u16 size;
    u64 offset;
} __attribute__((packed)) idtr_t;

int init_module(void) {
    idtr_t idtr;
    asm("sidt %0" : "=m"(idtr));
    printk("IDTR size: %u\n", idtr.size);
    printk("IDTR offset: 0x%llx\n", idtr.offset);

    int i;
    for (i = 0; i <= idtr.size / 16; i++) {
      u64 entry = *((u64 *)idtr.offset + i);
      if (entry != 0) {
        printk("Entry %d: 0x%llx\n", i, entry);
      }
    }
    return 0;
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
