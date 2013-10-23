/*	pcap-snmp-monitor/pcap-snmp-monitor.h

	Copyright 2013, iStream Financial Services, Inc.
	Author, Dennis Jenkins (dennis.jenkins.75 (at) gmail.com)
	Published with permission of iStream Financial Services, Inc.

	This software is licensed under the GPL v2.

	This software contains two components:

1) A daemon that captures ethernet packets on an interface, filters them via BPF,
   keeps running totals of bytes and packets that match each BPF.

2) A program to be used by net-snmp to get the latest counter values.
*/

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pcapnav.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

// http://www.net-snmp.org/wiki/index.php/TUT:Writing_a_Subagent

// Disable inlining in the SNMP headers.  Eliminates a LOT of compiler warnings.
#define NETSNMP_BROKEN_INLINE

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "snmp-mib.h"

// Gentoo package "dev-libs/confuse-2.6-r3"
#include <confuse.h>

// Get struct defs for ethernet, ip, tcp and udp headers
#include "ethernet.h"

#define MAX_DEVICES			16
#define DEFAULT_RUNAS_USER		"tcpdump"
#define DEFAULT_RUNAS_GROUP		"tcpdump"
#define DEFAULT_CONFIG_FILE		"/etc/pcap-snmp-monitor.conf"
#define DEFAULT_PID_FILE		"/var/run/pcap-snmp-monitor.pid"
#define DEFAULT_LOG_FILE		"/var/log/pcap-snmp-monitor.log"
#define DEFAULT_DAEMON_NAME		"pcap-snmp-monitor"
#define DEFAULT_SNMP_PERSISTENT_FILE	"/var/run/pcap-snmp-monitor/snmp.conf"

struct filter
{
	int			index;
	int			terminal;		// If packet is filtered here, skip remaining filters.
	const char		*name;
	const char		*bpf_text;
	struct bpf_program	*bpf;
	u_int64_t		bytes;
	u_int64_t		packets;
	struct filter		*next_filter;
	struct device		*parent_device;
};

struct device
{
	pcap_t			*pcap;
	int			pcap_fd;
	const char		*dev_name;
	struct filter		*first_filter;
	struct device		*next_device;
};

extern struct device	*g_pDeviceList;
