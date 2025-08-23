bin_PROGRAMS = $(top_builddir)/openBLAHAJ
AM_CFLAGS = -Wall -Wextra -I"$(top_srcdir)/include" -pedantic -Wconversion -Wno-cpp -Wno-padded -Wno-pedantic
AM_LDFLAGS = -export-dynamic

if STATIC_RELEASE
AM_LDFLAGS += -static
else
AM_LDFLAGS +=
endif

if BUILD_BLUETOOTH
BT_SOURCE = link/bluetooth.c
else
BT_SOURCE =
endif

if BUILD_DBUS
DBUS_SOURCE = link/dbus.c
else
DBUS_SOURCE =
endif

LIBRARY_SOURCES = \
transport/transport.c \
transport/ospf.c \
transport/icmp6.c \
transport/icmp.c \
transport/igmp.c \
transport/udp.c \
transport/tcp.c \
transport/sctp.c \
network/network.c \
network/ip4.c \
network/ip.c \
network/arp.c \
network/ip6.c \
link/link.c \
link/cooked.c \
link/eth.c \
link/pppoe.c \
link/ppp.c \
link/radiotap.c \
application/mqtt.c \
application/http.c \
application/ftp.c \
application/imap.c \
application/pop.c \
application/bootp.c \
application/ssdp.c \
application/smtp.c \
application/dhcp.c \
application/syslog.c \
application/ripng.c \
application/telnet.c \
application/whois.c \
application/wireguard.c \
application/application.c \
application/dns.c \
application/rip.c \
application/tls.c \
application/ntp.c \
application/quic.c \
application/http3.c \
generic/bytes.c \
generic/guid.c \
generic/dash.c \
generic/terminal.c \
generic/protocol.c \
generic/binary.c \
generic/time.c \
generic/thread.c \
openblahaj.c \
hooks/socket.c \
hooks/openssl.c \
hooks/quiche.c \
hooks/nss.c \
hooks/printbuf.c \
$(BT_SOURCE) \
$(DBUS_SOURCE)

lib_LTLIBRARIES = libopenBLAHAJ.la

libopenBLAHAJ_la_SOURCES = $(LIBRARY_SOURCES)

__top_builddir__openBLAHAJ_SOURCES = main.c
__top_builddir__openBLAHAJ_LDADD = libopenBLAHAJ.la

.PHONY: print
print:
	$(__top_builddir__openBLAHAJ_SOURCES)

.PHONY: install-exec-hook

install-exec-hook:
	setcap cap_net_raw=eip $(DESTDIR)$(bindir)/openBLAHAJ
	ldconfig
