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

typedef struct {
  u32 base_32_63;
  u32 reserved;
} gdt_sys_descriptor_higher;

typedef union {
  u64 scalar;
  gdt_descriptor_t structure;
  gdt_sys_descriptor_higher structure_higher;
} gdt_descriptor_u_t;

static inline u32 build_base(u16 base_0_15, u8 base_16_23, u8 base_24_31, u32 base_32_63) {
  return base_0_15 | (base_16_23 << 16) | (base_24_31 << 24) | (base_32_63 << 32);
}

static inline u32 build_limit(u16 limit_0_15, u8 limit_16_19) {
  return limit_0_15 | (limit_16_19 << 16);
}

typedef enum {
  LDT, TSS_AVAILABLE, TSS_BUSY
} system_segment_descriptor_type_t;

bool print_descriptor(gdt_descriptor_u_t desc, gdt_descriptor_u_t next_desc) {
  if (!desc.scalar) return false;
  bool is_system = !desc.structure.ab.s;
  printk("Segment type: ");
  printk(is_system ? KERN_CONT "System segment" : KERN_CONT "User segment");
  if (is_system) {
    system_segment_descriptor_type_t sys_desc_type;
    switch(desc.structure.ab.f4.sab) {
      case 0x2:
        sys_desc_type = LDT;
        printk("Type: LDT");
        break;
      case 0x9:
        sys_desc_type = TSS_AVAILABLE;
        printk("Type: TSS_AVAILABLE");
        break;
      case 0xB:
        sys_desc_type = TSS_BUSY;
        printk("Type: TSS_BUSY");
        break;
    }
  }
  u32 base = build_base(desc.structure.base_0_15, desc.structure.base_16_23, desc.structure.base_24_31, next_desc.structure_higher.base_32_63);
  printk("Base: 0x%x", base);
  u32 limit = build_limit(desc.structure.limit_0_15, desc.structure.limit_16_19);
  printk("Limit: 0x%x", limit);
  if (is_system) return true;
  return false;
}

int init_module(void) {
  gdtr_t gdtr;
  asm("sgdt %0" : "=m"(gdtr));
  printk("GDTR size: %u", gdtr.size);
  printk("GDTR offset: 0x%lx", gdtr.offset);
  WARN_ON(*((unsigned long *)gdtr.offset) != 0);

  int i;
  bool was_system = false;
  for (i = 0; i <= gdtr.size / 8; i++) {
    if (was_system) {
      was_system = false;
      continue;
    }
    printk("Entry %d: 0x%lx", i, *((unsigned long *)gdtr.offset + i));
    gdt_descriptor_u_t desc;
    desc.scalar = *((unsigned long *)gdtr.offset + i);
    gdt_descriptor_u_t next_desc;
    next_desc.scalar = *((unsigned long *)gdtr.offset + i + 1);
    was_system = print_descriptor(desc, next_desc);
  }

  return 0;
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
