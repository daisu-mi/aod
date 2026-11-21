# Build inside a FreeBSD 15.1 machine with /usr/src installed:
#   make && kldload ./aod.ko && sysctl net.inet.tcp.emu_kind=3
KMOD=	aod
SRCS=	aod.c aod.h

.include <bsd.kmod.mk>
