This project is a daemon that will analyze (but not record to disk)
network traffic using a user-supplied set of BPF expressions,
making the counts of packet matches and bytes available via net-snmp
so that they can be queried or graphed (eg, by cacti).

Created by Dennis Jenkins while at iStream Financial Services, Inc.
Released as open-source with permission of my employer.


1) Instlal these Gentoo packages (or more recent versions):
	net-libs/libnids-1.18
	dev-libs/confuse-2.6-r3
	net-libs/libpcap-1.0.0-r2
	net-libs/libpcapnav-0.7

2) "sudo emerge -avu libnids confuse libpcap libpcapnav"

3) Compile source code: "make"

4) Install binary: "sudo make install"

5) Modify "/etc/snmp/snmpd.conf", add "master agentx" near bottom.

6) Restart "snmpd"

7) Edit "/etc/pcap-snmp-monitor" (create some sample filters).

8) Test program "sudo /usr/local/sbin/pcap-snmp-monitor -v"

9) snmpwalk -On -c public -v 2c 127.0.0.1 .1.3.6.1.4.1.8072

10) Kill test process.

11) Add to gentoo startup: "sudo rc-update add pcap-snmp-monitor default"

12) Start as managed service (and retest) "sudo /etc/init.d/pcap-snmp-monitor start"
