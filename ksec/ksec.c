#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <net/genetlink.h>

enum {
  KSEC_A_UNSPEC,
  KSEC_A_MSG,
  __KSEC_A_MAX,
};
#define KSEC_A_MAX (__KSEC_A_MAX - 1)

enum {
  KSEC_C_UNSPEC,
  KSEC_C_CHECK_HIDDEN_MODULES,
  KSEC_C_CHECK_SYSCALLS,
  KSEC_C_CHECK_INTERRUPTS,
  KSEC_C_CHECK_FOPS,
  __KSEC_C_MAX,
};
#define KSEC_C_MAX (__KSEC_C_MAX - 1)

static struct nla_policy ksec_genl_policy[KSEC_A_MAX + 1] = {
  [KSEC_A_MSG] = { .type = NLA_NUL_STRING },
};

static int check_hidden_modules(struct sk_buff *, struct genl_info *);
static int check_syscalls(struct sk_buff *, struct genl_info *);
static int check_interrupts(struct sk_buff *, struct genl_info *);
static int get_idt_entries(struct sk_buff *, struct genl_info *);
static int check_fops(struct sk_buff *, struct genl_info *);

static struct genl_ops ksec_ops[] = {
  {
    .cmd = KSEC_C_CHECK_HIDDEN_MODULES,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = check_hidden_modules,
  },
  {
    .cmd = KSEC_C_CHECK_SYSCALLS,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = check_syscalls,
  },
  {
    .cmd = KSEC_C_CHECK_INTERRUPTS,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = check_interrupts,
  },
  {
    .cmd = KSEC_C_CHECK_FOPS,
    .flags = 0,
    .policy = ksec_genl_policy,
    .doit = check_fops,
  },
};

static struct genl_family ksec_genl_family = {
  .id = 0x0,
  .hdrsize = 0,
  .name = "ksec",
  .version = 1,
  .maxattr = KSEC_A_MAX,
  .ops = ksec_ops,
  .n_ops = 4,
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_kprobed;
typedef long (*sys_call_ptr_t)(const struct pt_regs *);
static sys_call_ptr_t *sys_call_table_resolved;
typedef int (*core_kernel_text_t)(unsigned long addr);
static core_kernel_text_t core_kernel_text_resolved;
typedef int (*core_kernel_data_t)(unsigned long addr);
static core_kernel_data_t core_kernel_data_resolved;
static unsigned __int128 *idt_table_resolved = NULL;
typedef struct module *(*get_module_from_addr_t)(unsigned long addr);
static get_module_from_addr_t get_module_from_addr_resolved;

char *hidden_modules[128] = {0};
int syscalls_outside_kernel[512] = {[0 ... 511] = -1};
int interrupts_outside_kernel[512] = {[0 ... 511] = -1};

static struct module *find_insert_module(const char *name) {
  struct module *list_mod = NULL;
  list_for_each_entry(list_mod, THIS_MODULE->list.prev, list)
    if (strcmp(list_mod->name, name) == 0)
      return list_mod;
  return NULL;
}

static int check_hidden_modules(struct sk_buff *skb, struct genl_info *info) {
  struct kset *mod_kset;
  struct kobject *cur, *tmp;
  struct module_kobject *kobj;
  size_t hidden_modules_index = 0;

  int i;
  for (i = 0; i < 128; i++)
    hidden_modules[i] = 0;

  mod_kset = kallsyms_lookup_name_kprobed("module_kset");
  if (!mod_kset)
    return 1;

  list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry){
    if (!kobject_name(tmp))
      break;

    kobj = container_of(tmp, struct module_kobject, kobj);

    if (kobj && kobj->mod && kobj->mod->name){
      if (!find_insert_module(kobj->mod->name))
        hidden_modules[hidden_modules_index++] = kobj->mod->name;
    }
  }

  struct sk_buff *reply_skb;
  int rc;
  void *msg_head;
  char *to_send = kmalloc(8192, GFP_KERNEL);

  for (i = 0; i < 128; i++) {
    if (hidden_modules[i] == 0) break;
    strcat(to_send, hidden_modules[i]);
  }

  reply_skb = genlmsg_new(8192, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s():\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_CHECK_HIDDEN_MODULES);
  if (msg_head == NULL) {
    rc = ENOMEM;
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  rc = nla_put_string(reply_skb, KSEC_A_MSG, to_send);
  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);

  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  return 0;
}

int itoa(int value, char *sp, int radix) {
  char tmp[16];
  char *tp = tmp;
  int i;
  unsigned v;

  int sign = (radix == 10 && value < 0);
  if (sign)
    v = -value;
  else
    v = (unsigned)value;

  while (v || tp == tmp) {
    i = v % radix;
    v /= radix;
    if (i < 10)
      *tp++ = i+'0';
    else
      *tp++ = i + 'a' - 10;
  }

  int len = tp - tmp;

  if (sign) {
    *sp++ = '-';
    len++;
  }

  while (tp > tmp)
    *sp++ = *--tp;

  return len;
}

static int check_syscalls(struct sk_buff *skb, struct genl_info *info) {
  int syscalls_outside_kernel_index = 0;
  int i;
  for (i = 0; i < NR_syscalls; i++)
    if (!core_kernel_text_resolved(sys_call_table_resolved[i]))
      syscalls_outside_kernel[syscalls_outside_kernel_index++] = i;

  struct sk_buff *reply_skb;
  int rc;
  void *msg_head;
  char *to_send = kmalloc(2048, GFP_KERNEL);

  for (i = 0; i < 512; i++) {
    if (syscalls_outside_kernel[i] == -1) break;
    char str[5];
    itoa(syscalls_outside_kernel[i], str, 10);
    strcat(to_send, str);
    strcat(to_send, ",");
  }

  reply_skb = genlmsg_new(8192, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s():\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_CHECK_SYSCALLS);
  if (msg_head == NULL) {
    rc = ENOMEM;
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  rc = nla_put_string(reply_skb, KSEC_A_MSG, to_send);
  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);

  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  return 0;
}

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
} __attribute__((packed)) idt_entry_t;

typedef union {
  unsigned __int128 scalar;
  idt_entry_t structure;
} idt_entry_u_t;

static inline u64 build_offset(idt_entry_u_t entry) {
  return entry.structure.offset_0_15 | (entry.structure.offset_16_31 << 16) | (entry.structure.offset_32_63 << 32);
}

typedef enum {
  Kernel,
  Module,
  Other
} IDT_entry_location;

typedef struct {
  u16 number;
  IDT_entry_location location;
  char *module_name;
  idt_entry_u_t entry;
} idt_entry_info_t;

idt_entry_info_t *idt_entry_info_arr[4096] = {0};

static int get_idt_entries(struct sk_buff *skb, struct genl_info *info) {
  int idt_entry_info_arr_i = 0;
  int i;
  for (i = 0; i < IDT_ENTRIES; i++) {
    idt_entry_info_t *entry_info = kmalloc(sizeof(idt_entry_info_t), GFP_KERNEL);
    entry_info->number = i;

    idt_entry_u_t entry;
    entry.scalar = idt_table_resolved[i];

    entry_info->entry = entry;

    if (entry.structure.ab.p)
      if (!core_kernel_text_resolved(build_offset(entry))) {
        struct module *module;
        module = get_module_from_addr_resolved(build_offset(entry));
        if (module) {
          entry_info->location = Module;
          entry_info->module_name = module->name;
        } else entry_info->location = Other;
      } else entry_info->location = Kernel;

    idt_entry_info_arr[idt_entry_info_arr_i++] = entry_info;
  }

  struct sk_buff *reply_skb;
  int rc;
  void *msg_head;
  char *to_send = kmalloc(sizeof(idt_entry_info_t) * idt_entry_info_arr_i + 1, GFP_KERNEL);

  for (i = 0; i < 4096; i++) {
    if (idt_entry_info_arr[i] == 0) break;
    // TODO
  }

  reply_skb = genlmsg_new(8192, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s():\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_CHECK_INTERRUPTS);
  if (msg_head == NULL) {
    rc = ENOMEM;
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  rc = nla_put_string(reply_skb, KSEC_A_MSG, to_send);
  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);

  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  return 0;
}

static int check_interrupts(struct sk_buff *skb, struct genl_info *info) {
  int interrupts_outside_kernel_index = 0;
  int i;
  for (i = 0; i < IDT_ENTRIES; i++) {
    idt_entry_u_t entry;
    entry.scalar = idt_table_resolved[i];
    if (entry.structure.ab.p)
      if (!core_kernel_text_resolved(build_offset(entry))) {
        interrupts_outside_kernel[interrupts_outside_kernel_index++] = i;
        struct module *module;
        module = get_module_from_addr_resolved(build_offset(entry));
        if (module)
          printk("Interrupt inside module named: %s\n", module->name);
        else
          printk("Interrupt outside kernel and modules, addr: 0x%x virt-addr: 0x%x\n", build_offset(entry), __va(build_offset(entry)));
      }
  }

  struct sk_buff *reply_skb;
  int rc;
  void *msg_head;
  char *to_send = kmalloc(2048, GFP_KERNEL);

  for (i = 0; i < 512; i++) {
    if (interrupts_outside_kernel[i] == -1) break;
    char str[5];
    itoa(interrupts_outside_kernel[i], str, 10);
    strcat(to_send, str);
    strcat(to_send, ",");
  }

  reply_skb = genlmsg_new(8192, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s():\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_CHECK_INTERRUPTS);
  if (msg_head == NULL) {
    rc = ENOMEM;
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  rc = nla_put_string(reply_skb, KSEC_A_MSG, to_send);
  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);

  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  return 0;
}

static int check_fops(struct sk_buff *skb, struct genl_info *info) {
  struct file *fp;

  fp = filp_open("/proc", O_RDONLY, S_IRUSR);
  if (IS_ERR_OR_NULL(fp)) {
    printk(KERN_ERR "Can't open /proc\n");
    return 1;
  }

  if (IS_ERR_OR_NULL(fp->f_op)) {
    printk(KERN_ERR "/proc fops is NULL\n");
    filp_close(fp, NULL);
    return 1;
  }

  int fops_iterate_is_outside_kernel = 0;
  if (!core_kernel_text_resolved(fp->f_op->iterate))
    fops_iterate_is_outside_kernel = 1;

  struct module *module;
  if (fops_iterate_is_outside_kernel)
     module = get_module_from_addr_resolved(fp->f_op->iterate);

  filp_close(fp, NULL);

  struct sk_buff *reply_skb;
  int rc;
  void *msg_head;
  char *to_send = kmalloc(2048, GFP_KERNEL);

  if (fops_iterate_is_outside_kernel && module) {
    strcat(to_send, "/proc fops iterate is outside kernel, within module named ");
    strcat(to_send, module->name) ;
  } else if (fops_iterate_is_outside_kernel) {
    strcat(to_send, "/proc fops iterate is outside kernel, not within a module");
  } else strcat(to_send, "/proc fops iterate is within kernel");

  reply_skb = genlmsg_new(8192, GFP_KERNEL);
  if (reply_skb == NULL) {
    pr_err("An error occurred in %s():\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(reply_skb, info->snd_portid, info->snd_seq + 1, &ksec_genl_family, 0, KSEC_C_CHECK_FOPS);
  if (msg_head == NULL) {
    rc = ENOMEM;
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  rc = nla_put_string(reply_skb, KSEC_A_MSG, to_send);
  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  genlmsg_end(reply_skb, msg_head);
  rc = genlmsg_reply(reply_skb, info);

  if (rc != 0) {
    pr_err("An error occurred in %s():\n", __func__);
    return -rc;
  }

  return 0;
}

void resolve_kallsyms_lookup_name(void) {
  static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
  };
  register_kprobe(&kp);
  kallsyms_lookup_name_kprobed = (kallsyms_lookup_name_t) kp.addr;
  unregister_kprobe(&kp);
}

static int __init modinit(void) {
  int rc;
  rc = genl_register_family(&ksec_genl_family);
  if (rc != 0) {
    pr_err("%s\n", "Couldn't register generic netlink family");
    return 1;
  }

  resolve_kallsyms_lookup_name();
  core_kernel_text_resolved = kallsyms_lookup_name_kprobed("core_kernel_text");
  core_kernel_data_resolved = kallsyms_lookup_name_kprobed("core_kernel_data");
  sys_call_table_resolved = kallsyms_lookup_name_kprobed("sys_call_table");
  idt_table_resolved = kallsyms_lookup_name_kprobed("idt_table");
  get_module_from_addr_resolved = kallsyms_lookup_name_kprobed("__module_address");

  return 0;
}

static void __exit modexit(void) {
  int rc = genl_unregister_family(&ksec_genl_family);
  if (rc !=0) {
    pr_err("%s\n", "Failed to unregister netlink family");
  }
}

module_init(modinit);
module_exit(modexit);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
