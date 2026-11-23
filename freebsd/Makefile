# Build inside a FreeBSD 15.1 machine with /usr/src installed:
#   make && kldload ./aod.ko && sysctl net.inet.tcp.emu_kind=8
KMOD=	aod
SRCS=	aod.c
CFLAGS+=	-I${.CURDIR}/../common

.include <bsd.kmod.mk>
