/* 
 * module_hunter.c: Search for patterns in the kernel address space that
 * look like module structures. This tools find hidden modules that
 * unlinked themself from the chained list of loaded modules.
 *
 * This tool is currently implemented as a module but can be easily ported
 * to a userland application (using /dev/kmem).
 * 
 * Compile with: gcc -c module_hunter.c -I/usr/src/linux/include
 * insmod ./module_hunter.o
 *
 * usage: cat /proc/showmodules && dmesg
 */

#define MODULE
#define __KERNEL__

#include <linux/config.h>

#ifdef CONFIG_SMP
#define __SMP__ 
#endif

#ifdef CONFIG_MODVERSIONS
#define MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/unistd.h>
#include <linux/string.h>


#include <linux/proc_fs.h>

#include <linux/errno.h>
#include <asm/uaccess.h>


#include <asm/pgtable.h>
#include <asm/fixmap.h>
#include <asm/page.h>

static int errno;


int valid_addr(unsigned long address)
{
    unsigned long page;

    if (!address)
        return 0;

    page = ((unsigned long *)0xc0101000)[address >> 22];        

    if (page & 1)
    {
        page &= PAGE_MASK;
        address &= 0x003ff000;
        page = ((unsigned long *) __va(page))[address >> PAGE_SHIFT];  //pte
        if (page)
            return 1;
    }
    
    return 0;
}

ssize_t
showmodule_read(struct file *unused_file, char *buffer, size_t len, loff_t *off)
{
    struct module *p;

    printk("address                         module\n\n");
    for (p=(struct module *)VMALLOC_START; p<=(struct \
module*)(VMALLOC_START+VMALLOC_RESERVE-PAGE_SIZE); p=(struct module \
*)((unsigned long)p+PAGE_SIZE))
    {
        if (valid_addr((unsigned long)p+ (unsigned long)&((struct \
module *)NULL)->name) && valid_addr(*(unsigned long *)((unsigned long)p+ \
(unsigned long)&((struct module *)NULL)->name)) && strlen(p->name))
            if (*p->name>=0x21 && *p->name<=0x7e && (p->size < 1 <<20))
                printk("0x%p%20s size: 0x%x\n", p, p->name, p->size);
    }

    return 0;
}

static struct file_operations showmodules_ops = {
    read:    showmodule_read,
};

int init_module(int x)
{
    struct proc_dir_entry *entry;

    entry = create_proc_entry("showmodules", S_IRUSR, &proc_root);
    entry->proc_fops = &showmodules_ops;

    return 0;
}

void cleanup_module()
{
    remove_proc_entry("showmodules", &proc_root);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("madsys<at>ercist.iscas.ac.cn");
