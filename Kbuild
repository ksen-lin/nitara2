MODNAME		?= nitara2


obj-m		+= $(MODNAME).o

ccflags-y	+= -Werror -fomit-frame-pointer 
# -D DEBUG

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
