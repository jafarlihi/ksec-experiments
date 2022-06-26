#include <linux/module.h>
#include <linux/types.h>
#include <asm/syscall.h>
#include <linux/kprobes.h>

int init_module(void) {
  static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
  };
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
  unregister_kprobe(&kp);

  sys_call_ptr_t *table = kallsyms_lookup_name("sys_call_table");
  printk("0x%x\n", table);

  printk("%d\n", __NR_syscalls);

  return 0;
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
