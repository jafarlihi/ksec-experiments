#include <linux/module.h>
#include <linux/types.h>

typedef struct {
    u16 size;
    unsigned __int128 offset;
} __attribute__((packed)) idtr_t;

typedef struct {
  u16 offset_0_15;
  u16 selector;
  struct access_byte {
    u8 ist : 2;
    u8 reserved : 4;
    u8 gate_type : 3;
    u8 zero : 1;
    u8 dpl : 1;
    u8 p : 1;
  } ab;
  u16 offset_16_31;
  u32 offset_32_63;
  u32 reserved;
} idt_entry_t;

typedef union {
  unsigned __int128 scalar;
  idt_entry_t structure;
} idt_entry_u_t;

int init_module(void) {
    idtr_t idtr;
    asm("sidt %0" : "=m"(idtr));

    int i;
    for (i = 0; i <= idtr.size / 16; i++) {
      idt_entry_u_t entry;
      entry.scalar = *((unsigned __int128 *)idtr.offset + i);
      printk("Entry %d: 0x%llx%llx\n", i, (u64)entry.scalar, (u64)(entry.scalar >> 64));
    }
    return 0;
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
