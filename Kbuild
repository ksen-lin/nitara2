MODNAME		?= nitara2

obj-m		+= $(MODNAME).o

ccflags-y	+= -Werror
# -D DEBUG

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
