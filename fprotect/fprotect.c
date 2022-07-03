#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

#include "queue.h"
#include "hashtab.h"
#include "str.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

char *rules = "rules";
module_param(rules, charp, S_IRUGO);

queue_t *write_queue;
hashtab_entry_t **perm_hashtab;

typedef long (*sys_call_ptr_t)(const struct pt_regs *);

static sys_call_ptr_t *syscall_table;
static sys_call_ptr_t openat;
static sys_call_ptr_t openat2;
static sys_call_ptr_t open_by_handle_at;
static sys_call_ptr_t open_tree;

static int misc_open(struct inode *inode, struct file *file) {
  return 0;
}

static int misc_close(struct inode *inodep, struct file *filp) {
  return 0;
}

static ssize_t misc_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos) {
  return len;
}

static ssize_t misc_read(struct file *file, char __user *out, size_t len, loff_t *ppos) {
  char *to_write = queue_dequeue(write_queue);
  size_t to_write_len = strlen(to_write);
  if (to_write == NULL)
    return 0;
  size_t could_not_be_copied = copy_to_user(out, to_write, to_write_len);
  return to_write_len - could_not_be_copied;
}

static const struct file_operations fops = {
  .owner = THIS_MODULE,
  .write = misc_write,
  .open = misc_open,
  .read = misc_read,
  .release = misc_close,
  .llseek = no_llseek,
};

struct miscdevice device = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "fprotect",
  .fops = &fops,
};

sys_call_ptr_t *get_syscall_table_addr(void) {
  static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
  };
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
  unregister_kprobe(&kp);
  return kallsyms_lookup_name("sys_call_table");
}

static void write_cr0_unsafe(unsigned long val) {
  asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
}

static long hooked_openat(const struct pt_regs *regs) {
  size_t comm_len = strlen(current->group_leader->comm);
  char *comm = kmalloc(comm_len + 1, GFP_KERNEL); // TODO: Handle allocation failure
  strncpy(comm, current->group_leader->comm, comm_len);
  comm[comm_len] = '\0';

  char __user *filename = (char *)regs->si;
  char user_filename[256] = {0};
  long copied = strncpy_from_user(user_filename, filename, sizeof(user_filename));
  size_t fn_len = strlen(user_filename);

  char *access_line = kmalloc(comm_len + 1 + fn_len + 2, GFP_KERNEL);
  strncpy(access_line, comm, comm_len);
  access_line[comm_len] = ' ';
  strncpy(access_line + comm_len + 1, user_filename, fn_len);
  access_line[comm_len + fn_len + 1] = '\n';
  access_line[comm_len + fn_len + 2] = '\0';

  queue_enqueue(write_queue, access_line);

  hashtab_entry_t *entry = hashtab_get(perm_hashtab, user_filename);
  int strcmp_result;
  while (strcmp_result = strcmp(entry->value, comm) && entry->next != NULL)
    entry->next;
  if (strcmp_result == 0)
    return openat(regs);

  return 1;
}

static int __init modinit(void) {
  write_queue = alloc_queue();

  unsigned long old_cr0;

  syscall_table = get_syscall_table_addr();

  old_cr0 = read_cr0();
  write_cr0_unsafe(old_cr0 & ~(X86_CR0_WP));

  openat = syscall_table[__NR_openat];
  syscall_table[__NR_openat] = hooked_openat;

  write_cr0_unsafe(old_cr0);

  int error = misc_register(&device);
  if (error) {
    pr_err("Can't register misc device\n");
    return error;
  }

  perm_hashtab = alloc_hashtab();
  size_t rule_count;
  char **rules_parts = split(rules, ',', &rule_count);
  int i;
  for (i = 0; i < rule_count; i++) {
    char *rule = rules_parts[i];
    char **rule_parts = split(rule, '=', NULL);
    hashtab_put(perm_hashtab, rule_parts[0], rule_parts[1]);
  }

  return 0;
}

static void __exit modexit(void) {
  // TODO: Free the queue
  misc_deregister(&device);

  unsigned long old_cr0 = read_cr0();
  write_cr0_unsafe(old_cr0 & ~(X86_CR0_WP));

  syscall_table[__NR_openat] = openat;

  write_cr0_unsafe(old_cr0);
}

module_init(modinit);
module_exit(modexit);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
