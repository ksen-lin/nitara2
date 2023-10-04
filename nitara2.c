/* 
 * original idea: madsys, "Finding hidden kernel modules (the extrem way)"
 *                http://phrack.org/issues/61/3.html
 *
 * usage: cat /proc/nitara2 && dmesg
 */

#include <asm/page.h>
#include <asm/fixmap.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
#  include <linux/mm.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#  include <linux/pgtable.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#  include <asm-generic/pgtable-nop4d.h>
#else /* < 4.11 */
// at this point Linux didn't have 5-level pgtables
#  include <asm/pgtable.h>
#endif

#include <linux/string.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <uapi/linux/stat.h>

#ifndef CONFIG_X86_64
#  error "arch not supported :("
#endif

#define NITARA_PRINTK(fmt, args...) printk("%s: " fmt, module_name(THIS_MODULE), ##args)
#define NITARA_MODSIZE (0x1000 * PAGE_SIZE)

/* https://patchwork.kernel.org/project/linux-fsdevel/patch/1515636190-24061-6-git-send-email-keescook@chromium.org/ */
#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

/* NOTE: arch-specific, we don't handle it properly yet */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0))
static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
{
	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
}

static __always_inline u64 __is_canonical_address(u64 vaddr, u8 vaddr_bits)
{
	return __canonical_address(vaddr, vaddr_bits) == vaddr;
}
#endif

#define is_canonical_48(p) __is_canonical_address((unsigned long)p, 48)
#define is_canonical_or_zero(p) (p == NULL || is_canonical_48(p))
#define is_canonical_high_or_zero(p) (p == NULL || ((unsigned long)p >= VMALLOC_START && is_canonical_48(p)))


/*
 * https://stackoverflow.com/questions/11134813/check-validity-of-virtual-memory-address
 * https://stackoverflow.com/questions/66593710/how-to-check-an-address-is-accessible-in-the-kernel-space
 * 
 * on 5-level paging introduction (6 Mar 2017, "patchset is build on top of v4.11-rc1"):
 * https://lwn.net/Articles/716324/
 */
static bool valid_addr(unsigned long addr, size_t size)
{
    pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    p4d_t *p4d;
#endif
    pmd_t *pmd;
    pud_t *pud;
    pte_t *pte;
    struct mm_struct *mm = current->mm;
    unsigned long end_addr;

    pgd = pgd_offset(mm, addr);
    if (unlikely(!pgd) || unlikely(pgd_none(*pgd)) || unlikely(!pgd_present(*pgd)) )
        return false;
        
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    p4d = p4d_offset(pgd, addr);
    if (unlikely(!p4d) || unlikely(p4d_none(*p4d)) || unlikely(!p4d_present(*p4d)) )
        return false;
    pud = pud_offset(p4d, addr);
#else
    pud = pud_offset(pgd, addr);
#endif
    if (unlikely(!pud) || unlikely(pud_none(*pud)) || unlikely(!pud_present(*pud)))
        return false;

    pmd = pmd_offset(pud, addr);
    if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) || unlikely(!pmd_present(*pmd)))
        return false;

    if (pmd_trans_huge(*pmd)) {
        end_addr = (((addr >> PMD_SHIFT) + 1) << PMD_SHIFT) - 1;
        goto end;
    }

    // NOTE: pte_offset_map() is unusable out-of-tree on >=6.5.
    //       As pte_offset_kernel() seems to work, use it instead ¯\_(ツ)_/¯
    pte = pte_offset_kernel(pmd, addr);
    if (unlikely(!pte) || unlikely(!pte_present(*pte)))
        return false;

    end_addr = (((addr >> PAGE_SHIFT) + 1) << PAGE_SHIFT) - 1;

end:
    if (end_addr >= addr + size - 1)
        return true;

    return valid_addr(end_addr + 1, size - (end_addr - addr + 1));
}


static bool is_within_modules(void *p)
{
    return (unsigned long)p >= MODULES_VADDR && (unsigned long)p < MODULES_END;
}


__maybe_unused static bool is_within_modules_or_zero(void *p)
{
    return p == NULL || is_within_modules(p);
}


static bool check_name_valid(char *s)
{
    size_t i;
    if (!s)
        return false;
    
    for (i = 0; i < sizeof_field(struct module, name); i += 1) {
        /* we might fail here if the name is "" */
        if (s[i] == '\0' && i != 0)
            break;
        if (s[i] < 0x20 || s[i] > 0x7e)
            return false;
    }
           
    return true;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define MODSIZE(p)                              \
       (p->mem[MOD_TEXT].size                   \
       + p->mem[MOD_INIT_TEXT].size             \
       + p->mem[MOD_INIT_DATA].size             \
       + p->mem[MOD_INIT_RODATA].size           \
       + p->mem[MOD_RO_AFTER_INIT].size         \
       + p->mem[MOD_RODATA].size                \
       + p->mem[MOD_DATA].size)
#else
#  define MODSIZE(p) (p->core_layout.size)
#endif


ssize_t showmodule_read(struct file *unused_file, char *buffer, size_t len, loff_t *off)
{
    struct module *p;
    unsigned long i;

    NITARA_PRINTK("address                           module size\n");
    for (
        i = 0, p = (struct module *)MODULES_VADDR;
        p <= (struct module*)(MODULES_END - 0x10);
        p = ((struct module*)((unsigned long)p + 0x10)), i += 1
    ) {
        if (
            valid_addr((unsigned long)p, sizeof(struct module))
            && p->state >= MODULE_STATE_LIVE && p->state <= MODULE_STATE_UNFORMED
            && check_name_valid(p->name)
            // may be unset for modules that can also be compiled as part of kernel (?)
            && is_within_modules_or_zero(p->init)
            && is_within_modules_or_zero(p->exit)
            && (p->init || p->exit || p->list.next || p->list.prev)
            // https://elixir.bootlin.com/linux/v5.19/source/include/linux/list.h#L146
            && (is_canonical_high_or_zero(p->list.next) || p->list.next == LIST_POISON1)
            && (is_canonical_high_or_zero(p->list.prev) || p->list.prev == LIST_POISON2)
            && MODSIZE(p) && (MODSIZE(p) % PAGE_SIZE == 0)
            // https://elixir.bootlin.com/linux/v5.15/source/kernel/module.c#L1130
            // && p->taints
        ) {
            NITARA_PRINTK("0x%lx: %20s %u\n", (unsigned long)p, p->name, MODSIZE(p));
        }
    }

    NITARA_PRINTK("end check (total gone %lu steps)\n", i);
    return 0;
}


#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 5, 19)
static struct proc_ops nitara2_ops = {
    .proc_read = showmodule_read,
    .proc_lseek	= default_llseek, // otherwise segfaults
};
#else /* < 4.20 (?!?) TODO: check creating proc entry for intermediate versions */ 
// include/linux/fs.h#L1692
static struct file_operations nitara2_ops = {
    .read = showmodule_read,
    .llseek	= default_llseek,
};
#endif


struct proc_dir_entry *entry;


int init_module()
{
    NITARA_PRINTK("[creating proc entry]\n");
    entry = proc_create_data("nitara2", S_IRUSR, NULL, &nitara2_ops, NULL);

    return 0;
}


void cleanup_module()
{
    NITARA_PRINTK("[cleanup proc]\n");
    proc_remove(entry);
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("ksen-lin");
