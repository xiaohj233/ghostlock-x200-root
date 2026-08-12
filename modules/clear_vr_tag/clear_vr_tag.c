// clear_vr_tag.c - vr.ko anti-root tag clearing module (vivo X200 b57)
// kretprobe on commit_creds: after any process commits root creds (which
// vivo vr.ko marks via task+0x06/task+0x2c and then kills at sys_exit via
// an inline hook in syscall_trace_exit), immediately clear:
//   - task+0x06  (VR_TAG_A)
//   - task+0x2c  (VR_TAG_B)
//   - thread_info.flags bit 0x400 (TIF_SYSCALL_TRACEPOINT, disables the
//     syscall trace path so vr.ko's sys_exit probe never runs for this task)
// Usage: insmod clear_vr_tag.ko cc_addr=0x<commit_creds VA of current boot>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

static unsigned long cc_addr;
module_param(cc_addr, ulong, 0);
MODULE_PARM_DESC(cc_addr, "commit_creds VA for current boot (from kallsyms)");

/* vr.ko anti-root offsets (auto-extracted by tools/offset_tools/extract_vr_offsets.py;
 * defaults are the b57 empirical values verified against the shipped vr.ko) */
static unsigned long tag_a_off = 0x06;
module_param(tag_a_off, ulong, 0);
MODULE_PARM_DESC(tag_a_off, "vr.ko tag A offset in task_struct");
static unsigned long tag_b_off = 0x2c;
module_param(tag_b_off, ulong, 0);
MODULE_PARM_DESC(tag_b_off, "vr.ko tag B offset in task_struct");
static unsigned long flags_off = 0x0;
module_param(flags_off, ulong, 0);
MODULE_PARM_DESC(flags_off, "task thread_info.flags offset");
static unsigned long tp_flag = 0x400;
module_param(tp_flag, ulong, 0);
MODULE_PARM_DESC(tp_flag, "vr.ko syscall tracepoint flag bit");

static unsigned long vr_pre_uid;

static int vr_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/* record euid before commit_creds */
	vr_pre_uid = current_euid().val;
	return 0;
}

static int vr_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *t = current;
	unsigned long *fp = (unsigned long *)((char *)t + flags_off);

	/* Only act on a real privilege escalation: euid went from non-root to root.
	 * root->root (zygote/init) and non-root->non-root commits must be left
	 * untouched, otherwise KernelSU's syscall hooking for the whole app chain
	 * breaks (manager never gets its ksu fd installed). */
	if (vr_pre_uid == 0 || current_euid().val != 0)
		return 0;

	/* clear syscall tracepoint flag first (no sys_exit probe for this task) */
	*fp &= ~tp_flag;
	/* clear vr.ko commit_creds tags */
	*(volatile unsigned char *)((char *)t + tag_a_off) = 0;
	*(volatile unsigned char *)((char *)t + tag_b_off) = 0;
	return 0;
}

static struct kretprobe krp = {
	.entry_handler = vr_entry_handler,
	.handler = vr_ret_handler,
	.maxactive = 32,
};

static int __init cvt_init(void)
{
	if (!cc_addr) {
		pr_err("clear_vr_tag: cc_addr not set\n");
		return -EINVAL;
	}
	krp.kp.addr = (void *)cc_addr;
	return register_kretprobe(&krp);
}

static void __exit cvt_exit(void)
{
	unregister_kretprobe(&krp);
}

module_init(cvt_init);
module_exit(cvt_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vr.ko anti-root tag clearing (b57)");
