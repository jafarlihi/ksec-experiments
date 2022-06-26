#include <linux/module.h>
#include <linux/types.h>

typedef struct {
    u16 size;
    unsigned __int128 offset;
} __attribute__((packed)) idtr_t;

int init_module(void) {
    idtr_t idtr;
    asm("sidt %0" : "=m"(idtr));

    int i;
    for (i = 0; i <= idtr.size / 16; i++) {
      unsigned __int128 entry = *((unsigned __int128 *)idtr.offset + i);
      if (entry != 0) {
        printk("Entry %d: 0x%llx%llx\n", i, entry, entry >> 64);
      }
    }
    return 0;
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
