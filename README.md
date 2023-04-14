# nitara2

a rebirth of `module_hunter` from [Finding hidden kernel modules (the extrem way)](http://phrack.org/issues/61/3.html) by `madsys` for modern kernels on x86_64.

* traverses virtual memory looking for stray `struct module`'s with some sane-looking fields
* `cat /proc/nitara2 && dmesg`

As the original module was written at the time of 2.2—2.4 kernels and IA32 architecture, there were several challenges encountered to get it to work:

* `struct module` has been heavily reworked and extended over the years. For example, there is no more `size` field, but many others were added; also kernel module loader was rewritten shortly after the original article was published 
* memory management on x64 differs from that on i386, so checking for page presence needs to be reimplemented
* module descriptor structs seem to get allocated within module mapping area and not vmalloc region, as was in the original work (see [Memory layout of x86-64](https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt))
* module mapping area on x64 is about 12 times larger than vmalloc area on i386 (1520 MB vs 128M, regardless of paging levels), so more checks need to be done to eliminate false positives that become more possible with a larger region, still without introducing false negatives.

Tested on 5.19 kernel.
