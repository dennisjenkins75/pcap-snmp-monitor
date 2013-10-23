MYFLAGS:=	-pg -ggdb -O2 -Wall -pipe -D_GNU_SOURCE
SNMPCFLAGS:=	`net-snmp-config --base-cflags`
SNMPLDFLAGS:=	`net-snmp-config --agent-libs`

CFLAGS:=	$(MYFLAGS) $(SNMPCFLAGS) --std=c99
CXXFLAGS:=	$(MYFLAGS) $(SNMPCFLAGS) -Wno-write-strings

OUT_DIR:=	.
PREFIX:=	/usr/local

RUNAS_USER:=	tcpdump
RUNAS_GROUP:=	tcpdump
PID_DIR:=	/var/run/pcap-snmp-monitor

#
# Target aliases
#

DAEMON:=	$(OUT_DIR)/pcap-snmp-monitor

TARGETS:=	$(DAEMON)

.PHONY:		all clean install

all:		$(TARGETS)

clean:
	rm -f $(TARGETS)
	find . -name "*.[oa]" -o -name "core" | xargs rm -f


##########################################################################
##########################################################################

DAEMON_SRC:=	daemon snmp-mib

DAEMON_OBJ:=	$(DAEMON_SRC:=.o)

$(DAEMON):	$(DAEMON_OBJ)
	$(CC) -pg -o $@ $(DAEMON_OBJ) -lpcap -lpcapnav -lconfuse $(SNMPLDFLAGS)

$(DAEMON_OBJ):	snmp-mib.h pcap-snmp-monitor.h

##########################################################################
##########################################################################

install:	$(DAEMON)
	install -m 755 -o root -g root $(DAEMON) $(PREFIX)/sbin/pcap-snmp-monitor
	install -m 755 -o root -g root gentoo-init-script /etc/init.d/pcap-snmp-monitor
	install -m 755 -o $(RUNAS_USER) -g $(RUNAS_GROUP) -d $(PID_DIR)
	touch /var/log/pcap-snmp-monitor.log
	chown $(RUNAS_USER):$(RUNAS_GROUP) /var/log/pcap-snmp-monitor.log
	if [ ! -f /etc/conf.d/pcap-snmp-monitor ]; then install -m 644 -o root -g root gentoo-conf /etc/conf.d/pcap-snmp-monitor; fi
