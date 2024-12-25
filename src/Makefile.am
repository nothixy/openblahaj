bin_PROGRAMS = $(top_builddir)/openBLAHAJ
AM_CFLAGS = -Wall -Wextra -I"$(top_srcdir)/include" -pedantic -Wconversion -Wno-cpp -Wno-padded -Wno-pedantic
AM_LDFLAGS = -I"$(top_srcdir)/include"

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

__top_builddir__openBLAHAJ_SOURCES = \
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
generic/bytes.c \
generic/guid.c \
generic/dash.c \
generic/terminal.c \
generic/protocol.c \
generic/binary.c \
generic/time.c \
generic/thread.c \
openblahaj.c \
$(BT_SOURCE) \
$(DBUS_SOURCE)

.PHONY: print
print:
	$(__top_builddir__openBLAHAJ_SOURCES)

.PHONY: install-exec-hook

install-exec-hook:
	setcap cap_net_raw=eip $(DESTDIR)$(bindir)/openBLAHAJ
