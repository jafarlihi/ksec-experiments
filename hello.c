#include <linux/module.h>
#include <linux/types.h>

typedef struct {
  unsigned short size;
  unsigned long offset;
} __attribute__((packed)) gdtr_t;

typedef struct {
  u16 limit_0_15;
  u16 base_0_15;
  u8 base_16_23;
  struct access_byte {
    union {
      struct user_ab {
        u8 access : 1;
        u8 rw : 1;
        u8 dc : 1;
        u8 ex : 1;
      } uab;
      u8 sab : 4;
    } f4;
    u8 s : 1;
    u8 privl : 2;
    u8 pr : 1;
  } ab;
  union {
    u8 limit_16_19 : 4;
    struct flags {
      u8 unused : 4;
      u8 zero : 1;
      u8 l : 1;
      u8 sz : 1;
      u8 gran : 1;
    } fl;
  };
  u8 base_24_31;
} gdt_descriptor_t;

typedef union {
  u64 scalar;
  gdt_descriptor_t structure;
} gdt_descriptor_u_t;

static inline u32 build_base(u16 base_0_15, u8 base_16_23, u8 base_24_31) {
  return base_0_15 | (base_16_23 << 16) | (base_24_31 << 24);
}

static inline u32 build_limit(u16 limit_0_15, u8 limit_16_19) {
  return limit_0_15 | (limit_16_19 << 16);
}

void print_descriptor(gdt_descriptor_u_t desc) {
  if (!desc.scalar) return;
  u32 base = build_base(desc.structure.base_0_15, desc.structure.base_16_23, desc.structure.base_24_31);
  printk("Base: 0x%x\n", base);
  u32 limit = build_limit(desc.structure.limit_0_15, desc.structure.limit_16_19);
  printk("Limit: 0x%x\n", limit);
  printk("Access Byte:\n");
  printk(desc.structure.ab.s ? "System segment" : "User segment");
}

int init_module(void) {
  gdtr_t gdtr;
  asm("sgdt %0" : "=m"(gdtr));
  printk("GDTR size: %u\n", gdtr.size);
  printk("GDTR offset: 0x%lx\n", gdtr.offset);
  WARN_ON(*((unsigned long *)gdtr.offset) != 0);

  int i;
  for (i = 0; i <= gdtr.size; i++) {
    printk("Entry %d: 0x%lx\n", i, *((unsigned long *)gdtr.offset + i));
    gdt_descriptor_u_t desc;
    desc.scalar = *((unsigned long *)gdtr.offset + i);
    print_descriptor(desc);
  }

  return 0;
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
