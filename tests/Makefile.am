TEST_EXTENSIONS = .ftest .stest .cap

TESTS_ENVIRONMENT = V2VALGRIND='$(VALGRIND_LOG_COMPILER) $(LOG_FLAGS)'

STEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' LOG_VALGRIND='$(VALGRIND_LOG_COMPILER) $(LOG_FLAGS)' $(SHELL) \
                  $(top_srcdir)/build-aux/tap-driver.sh
FTEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' LOG_VALGRIND='$(VALGRIND_LOG_COMPILER) $(LOG_FLAGS)' $(SHELL) \
                  $(top_srcdir)/build-aux/tap-driver.sh

CAP_LOG_COMPILER = ./capture.test

FTEST_LOG_DRIVER_FLAGS = --expect-failure yes

TESTS = commandline2.stest commandline1.ftest
TESTS += \
captures/airtunes.cap \
captures/ARP.cap \
captures/Bluetooth2.cap \
captures/Bluetooth.cap \
captures/DHCP_Auth.cap \
captures/DHCP.cap \
captures/DHCP-DYNDNS.cap \
captures/DHCPv6_1.cap \
captures/DHCPv6.cap \
captures/DNS.cap \
captures/empty.cap \
captures/FTP.cap \
captures/FTPv6-1.cap \
captures/FTPv6-2.cap \
captures/http.cap \
captures/HTTP.cap \
captures/HTTPS.cap \
captures/HTTP_TCP_SPLIT.cap \
captures/HTTPv6.cap \
captures/ICMP.cap \
captures/ICMPv6.cap \
captures/IGMP.cap \
captures/IMAP.cap \
captures/IPSec1.cap \
captures/IPSec2.cap \
captures/IPSec3.cap \
captures/IPSec5.cap \
captures/ipv4frags.cap \
captures/IPv6.cap \
captures/IPv6_Extensions_2.cap \
captures/IPv6_Extensions.cap \
captures/Netlink.cap \
captures/NFLOG.cap \
captures/NFqueue.cap \
captures/OSPF2.cap \
captures/OSPF3.cap \
captures/OSPF.cap \
captures/POP3.cap \
captures/RIPng.cap \
captures/RIP_v1.cap \
captures/SCTP.cap \
captures/SCTP_HTTP.bak.cap \
captures/SCTP_HTTP.cap \
captures/SCTP_MULTI.cap \
captures/SMTP.cap \
captures/SpanningTree.cap \
captures/SSDP.cap \
captures/stp.cap \
captures/Telnet_cooked.cap \
captures/Telnet_raw.cap \
captures/Whois.cap

EXTRA_DIST = $(TESTS) captures/
