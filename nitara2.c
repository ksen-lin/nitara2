/* 
 * original idea: madsys, "Finding hidden kernel modules (the extrem way)"
 *                http://phrack.org/issues/61/3.html
 *
 * usage: cat /proc/nitara2 && dmesg
 */


#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/fixmap.h>

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/pgtable.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/version.h>

#include <uapi/linux/stat.h>

// TODO: add ifdef DEBUG
#define NITARA_PRINTK(fmt, args...) printk("%s: %s():\t" fmt, module_name(THIS_MODULE), __func__, ##args)

#ifndef __canonical_address
static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
{
	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
}
#endif /* __canonical_address */

#ifndef __is_canonical_address
static __always_inline u64 __is_canonical_address(u64 vaddr, u8 vaddr_bits)
{
	return __canonical_address(vaddr, vaddr_bits) == vaddr;
}
#endif /* __is_canonical_address */

#define is_canonical_48(p) __is_canonical_address((unsigned long)p, 48)
#define is_canonical_or_zero(p) (p == NULL || is_canonical_48(p))
#define is_canonical_high_or_zero(p) (p == NULL || ((unsigned long)p >= VMALLOC_START && is_canonical_48(p)))


/*
 * https://stackoverflow.com/questions/11134813/check-validity-of-virtual-memory-address
 * https://stackoverflow.com/questions/66593710/how-to-check-an-address-is-accessible-in-the-kernel-space
 */
static bool page_mapping_exist(unsigned long addr, size_t size)
{
    pgd_t *pgd;
	p4d_t *p4d;
    pmd_t *pmd;
    pud_t *pud;
    pte_t *pte;
    struct mm_struct *mm = current->mm;
    unsigned long end_addr;

    pgd = pgd_offset(mm, addr);
    if (unlikely(!pgd) || unlikely(pgd_none(*pgd)) || unlikely(!pgd_present(*pgd)) )
        return false;

    p4d = p4d_offset(pgd, addr); // TODO: add check for CONFIG_PGTABLE_LEVELS ?
    if (unlikely(!p4d) || unlikely(p4d_none(*p4d)) || unlikely(!p4d_present(*p4d)) )
        return false;
    
    pud = pud_offset(p4d, addr);
    if (unlikely(!pud) || unlikely(pud_none(*pud)) || unlikely(!pud_present(*pud)))
        return false;

    pmd = pmd_offset(pud, addr);
    if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) || unlikely(!pmd_present(*pmd)))
        return false;

    if (pmd_trans_huge(*pmd)) {
        end_addr = (((addr >> PMD_SHIFT) + 1) << PMD_SHIFT) - 1;
        goto end;
    }

    pte = pte_offset_map(pmd, addr);
    if (unlikely(!pte) || unlikely(!pte_present(*pte)))
        return false;

    end_addr = (((addr >> PAGE_SHIFT) + 1) << PAGE_SHIFT) - 1;

end:
    if (end_addr >= addr + size - 1)
        return true;

    return page_mapping_exist(end_addr + 1, size - (end_addr - addr + 1));
}


static bool addr_valid_x64(unsigned long addr, size_t size)
{
    // int i;
    // for (i = 0; i < size; i++)
    //     if (!virt_addr_valid(addr + i)) {            // <------ returns true only for addresses within kernel
    //         NITARA_PRINTK("[-] %#lx[%i]: virt_addr_valid() false\n", addr, i);
    //         return false;
    //     }

    if (!page_mapping_exist(addr, size))
        return false;

    return true;
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
        if (s[i] == '\0' && i != 0)
            break;

        if (s[i] < 0x20 || s[i] > 0x7e)
            return false;
    }
            
    return true;
}


ssize_t showmodule_read(struct file *unused_file, char *buffer, size_t len, loff_t *off)
{
    struct module *p;
    unsigned long i;

    NITARA_PRINTK("address                         module\n");

    for (
        i = 0, p = (struct module *)MODULES_VADDR;
        p <= (struct module*)(MODULES_END - 0x10);
        p = ((struct module*)((unsigned long)p + 0x10))
    ) {

#ifdef NITARA_DEBUG
        if (((unsigned long)p % (PAGE_SIZE)) == 0)
            NITARA_PRINTK("checking 0x%llx (p->name at %#lx)\n", (unsigned long long)p, (unsigned long)&(p->name));
#endif
        if (
            addr_valid_x64((unsigned long)p, sizeof(struct module))
            && p->state >= MODULE_STATE_LIVE && p->state <= MODULE_STATE_UNFORMED
            && check_name_valid(p->name)
            && is_within_modules_or_zero(p->init) // may be unset for modules that can also be compiled as part of kernel
            && (p->exit || p->list.next || p->list.prev)
            && is_canonical_high_or_zero(p->list.next) 
            && is_canonical_high_or_zero(p->list.prev) 
            && is_canonical_high_or_zero(p->exit)
            && is_canonical_or_zero(p->args)
            // && is_canonical_high_or_zero(p->version)
            && is_canonical_high_or_zero(p->syms) // at least init() must be...
            // && is_canonical_high_or_zero(p->kp)
            // || is_canonical_high_or_zero(p->crcs))
            // && is_canonical_high_or_zero(p->modinfo_attrs) // should not be messed with
            // && is_canonical_high_or_zero(p->srcversion) // should not be messed with
            // && is_canonical_high_or_zero(p->holders_dir)// should not be messed with
            && is_within_modules_or_zero(p->exit)
            && (is_within_modules_or_zero(p->list.next) || is_within_modules_or_zero(p->list.prev))
            && (p->init_layout.size + p->core_layout.size  < 0x200 * PAGE_SIZE) // 2 MiB
            && (p->init_layout.size + p->core_layout.size  >= 2 * PAGE_SIZE)
            // && p->taints // NOTE: https://elixir.bootlin.com/linux/v5.15/source/kernel/module.c#L1130
            && module_refcount(p) < 32
        ) {
            NITARA_PRINTK("0x%lx: \"%s\",\tnext %#lx, prev %#lx exit %#lx\n", 
                            (unsigned long)p,
                            p->name,
                            (unsigned long)p->list.next,
                            (unsigned long)p->list.prev,
                            (unsigned long)p->exit);
        }
        i += 1;
    }

    NITARA_PRINTK("end check (total gone %lu steps)\n", i);

    return 0;
}


static struct proc_ops nitara2_ops = {
    .proc_read = showmodule_read,
    .proc_lseek	= default_llseek, // otherwise segfaults
};


struct proc_dir_entry *entry;


int init_module()
{
    NITARA_PRINTK("starting\n");
    entry = proc_create_data("nitara2", S_IRUSR, NULL, &nitara2_ops, NULL);

    return 0;
}


void cleanup_module()
{
    NITARA_PRINTK("cleanup...\n");
    proc_remove(entry);
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("ksen-lin");
