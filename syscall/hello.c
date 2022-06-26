#include <linux/module.h>
#include <linux/types.h>
#include <asm/syscall.h>
#include <linux/kprobes.h>
#include <linux/swap.h>

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
  sys_call_ptr_t *initial_table = kmalloc(__NR_syscalls * sizeof(sys_call_ptr_t));
  memcpy(initial_table, table, __NR_syscalls * sizeof(sys_call_ptr_t));

  return 0;
}

void cleanup_module(void) {
}

MODULE_LICENSE("GPL");
