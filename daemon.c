/*	pcap-snmp-monitor/daemon.c

	Copyright 2013, iStream Financial Services, Inc.
	Author, Dennis Jenkins (dennis.jenkins.75 (at) gmail.com)
	Published with permission of iStream Financial Services, Inc.

	This software is licensed under the GPL v2.

	This software contains two components:

1) A daemon that captures ethernet packets on an interface, filters them via BPF,
   keeps running totals of bytes and packets that match each BPF.

2) A program to be used by net-snmp to get the latest counter values.

*/

#include "pcap-snmp-monitor.h"

// Set via command line options.
static int _daemon = 0;
static int verbose = 0;
static int force = 0;
static int do_snmp = 1;
static char *pid_file = DEFAULT_PID_FILE;
static char *config_file = DEFAULT_CONFIG_FILE;
static char *runas_user = DEFAULT_RUNAS_USER;
static char *runas_group = DEFAULT_RUNAS_GROUP;
static char *log_file = DEFAULT_LOG_FILE;
static char *daemon_name = DEFAULT_DAEMON_NAME;
static char *snmp_persistent_file = DEFAULT_SNMP_PERSISTENT_FILE;

// Internal.
static const int pcap_timeout = 2500;
static volatile int g_shutdown = 0;
static uid_t runas_uid = -1;
static gid_t runas_gid = -1;

// Global (public symbols)
struct device *g_pDeviceList = NULL;


// Input: bpf expression of form "xxx"
// Output: bpf expression of form "(xxx) or (yyy)", where yyy = xxx with src/dst replaced with dst/src.
char*	bpf_mirror (const char *bpf_src)
{
	char	*mirror = strdup(bpf_src);
	char	*result = (char*)malloc(strlen(bpf_src) * 2 + 32); 	// "+9 should be enough..?"
	char	*a, *p, *q;

	a = mirror;
	p = strstr(a, "dst");
	q = strstr(a, "src");

	while (p || q)
	{
		if ((q && !p) || (q && (q < p)))
		{
			memcpy (q, "dst", 3);
			q = strstr (q + 3, "src");
			continue;
		}

		if ((p && !q) || (p && (p < q)))
		{
			memcpy (p, "src", 3);
			p = strstr (p + 3, "dst");
			continue;
		}

		fprintf (stderr, "crap. mirror, q, p, q = %p, %p, %p, %p\n", mirror, q, p, q);
		exit (-1);
	}

	if (strcmp (bpf_src, mirror))	// did we make any changes?
	{
		sprintf (result, "(%s) or (%s)", bpf_src, mirror);
		return result;
	}

	free (result);
	return strdup(bpf_src);
}


static cfg_opt_t filter_opts[] =
{
	CFG_STR ("bpf", "", CFGF_NONE),
	CFG_INT ("oid", 0, CFGF_NONE),
	CFG_INT ("terminal", 1, CFGF_NONE),
	CFG_END ()
};

static cfg_opt_t device_opts[] =
{
	CFG_SEC ("filter", filter_opts, CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
	CFG_END ()
};

static cfg_opt_t opts[] =
{
	CFG_SEC ("device", device_opts, CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
	CFG_END ()
};

void	process_cfg_file (const char *cfg_file)
{
	cfg_t		*conf = NULL;		// libconfuse
	int		ok = 1;
	int		cnt_devices = 0;
	int		filter_index = 1;
	pcap_t		*pcap = NULL;

	pcap = pcap_open_dead (DLT_EN10MB, 65536);	// Dummy capture device.

	if (NULL == (conf = cfg_init (opts, CFGF_NONE)))
	{
		fprintf (stderr, "cfg_init() failed unexpectedly.\n");
		pcap_close (pcap);
		exit (-1);
	}

	ok = cfg_parse (conf, cfg_file);

	if (CFG_PARSE_ERROR == ok)
	{
		fprintf (stderr, "failed to parse '%s'.\n", cfg_file);
		pcap_close (pcap);
		exit (-1);
	}
	else if (CFG_FILE_ERROR == ok)
	{
		fprintf (stderr, "file error parsing '%s'.\n", cfg_file);
		perror (cfg_file);
		pcap_close (pcap);
		exit (-1);
	}

	cnt_devices = cfg_size (conf, "device");

	if (!cnt_devices)
	{
		fprintf (stderr, "Error - no devices defined in config file '%s'.\n", cfg_file);
		pcap_close (pcap);
		exit (-1);
	}

	struct device *prev_device = NULL;
	for (int d = 0; d < cnt_devices; d++)
	{
		cfg_t *d_iter = cfg_getnsec (conf, "device", d);
		struct filter *last_filter = NULL;
		struct device *dev = (struct device*)malloc (sizeof (struct device));

		memset (dev, 0, sizeof (struct device));
		dev->pcap = NULL;
		dev->pcap_fd = -1;
		dev->dev_name = strdup(cfg_title (d_iter));
		dev->first_filter = NULL;
		dev->next_device = NULL;

		if (prev_device)
		{
			prev_device->next_device = dev;
			prev_device = dev;
		}
		else
		{
			g_pDeviceList = dev;
			prev_device = dev;
		}

		int cnt_filters = cfg_size (d_iter, "filter");
		for (int f = 0; f < cnt_filters; f++)
		{
			cfg_t *f_iter = cfg_getnsec (d_iter, "filter", f);
			char *alt_src = NULL;
			const char *bpf_text = cfg_getstr (f_iter, "bpf");
			const char *name = cfg_title (f_iter);
			int oid_value = cfg_getint (f_iter, "oid");
			int terminal = cfg_getint (f_iter, "terminal");

			struct bpf_program *bpf = (struct bpf_program*) malloc (sizeof (struct bpf_program));

			alt_src = bpf_mirror (bpf_text);

			if (-1 == pcap_compile (pcap, bpf, alt_src ? alt_src : bpf_text, 1, 0))
			{
				fprintf (stderr, "BPF syntax error in filter for '%s':\n%s\n", name, pcap_geterr (pcap));
				free (bpf);
				if (alt_src) free (alt_src);
				continue;
			}

			struct filter *flt = (struct filter*)malloc (sizeof (struct filter));
			memset (flt, 0, sizeof (struct filter));
			flt->name = strdup (name);
			flt->terminal = terminal;
			flt->bpf_text = strdup (bpf_text);
			flt->bpf = bpf;
			flt->bytes = 0;
			flt->packets = 0;
			flt->next_filter = NULL;
			flt->parent_device = dev;
			flt->index = oid_value ? oid_value : filter_index++;

			if (last_filter)
			{
				last_filter->next_filter = flt;
				last_filter = flt;
			}
			else
			{
				dev->first_filter = flt;
				last_filter = flt;
			}

			if (alt_src) free (alt_src);
		}
	}

	pcap_close (pcap);
	cfg_free (conf);
}


void	callback (u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct device *d = (struct device*)args;
	struct filter *f = NULL;

	for (f = d->first_filter; f; f = f->next_filter)
	{
		if (pcap_offline_filter (f->bpf, hdr, pkt))
		{
			f->bytes += hdr->len;
			f->packets ++;

			if (verbose > 1)
			{
				fprintf (stderr, "Match: [%d,%s] = %u (total = %llu)\n",
					f->index, f->name, hdr->len, f->bytes);
			}

			if (f->terminal)
			{
				return;
			}
		}
	}
}

static int sig_list[] =
{ SIGHUP, SIGINT, SIGTERM, 0 };

void	handler_shutdown (int n)
{
	int	i;

	if (verbose)
	{
		fprintf (stderr, "signal (%d), shutting down.\n", n);
	}

// Let next signal kill process via default handler.
	for (i = 0; sig_list[i]; i++)
	{
		signal (sig_list[i], SIG_DFL);
	}

	g_shutdown = 1;
}

void	handler_usr1 (int n)
{
	struct device	*d = NULL;
	struct filter	*f = NULL;
	FILE		*fp = stderr;
	char		temp[256];
	struct tm	*tm = NULL;
	time_t		t = 0;

	if (_daemon)
	{
		t = time(NULL);
		tm = localtime (&t);

		snprintf (temp, sizeof (temp), "/tmp/pcap-snmp.usr1.%d", getpid());
		if (NULL == (fp = fopen (temp, "wt"))) return;

		strftime (temp, sizeof (temp), "%Y-%m-%d %H:%M:%S", tm);
		fprintf (fp, "# %lu %s\n", (unsigned long)t, temp);
	}
	else
	{
		fprintf (fp, "-------------------\n");
	}

	for (d = g_pDeviceList; d; d = d->next_device)
	{
		for (f = d->first_filter; f; f = f->next_filter)
		{
			fprintf (fp, "%s, %s, %d, %llu, %llu\n", d->dev_name, f->name, f->terminal, f->packets, f->bytes);
		}
	}

	if (_daemon)
	{
		fclose (fp);
	}
}

void	create_pid_file (void)
{
	FILE		*fp_pid = NULL;
	int		fd = -1;

	if (-1 == (fd = open (pid_file, O_CLOEXEC | O_CREAT | O_EXCL | O_NOATIME | O_NOFOLLOW | O_RDWR, 0644)))
	{
		fprintf (stderr, "Failed to create pid file: %s\n", pid_file);
		perror ("open");
		exit (EXIT_FAILURE);
	}

// Need to chown the PID file, or we won't be able to nuke it once we 'setuid'.
	if (-1 == fchown (fd, runas_uid, runas_gid))
	{
		fprintf (stderr, "Failed to set ownership of pid file ('%s') to '%d:%d'\n", pid_file, runas_uid, runas_gid);
		perror ("fchown");
		exit (EXIT_FAILURE);
	}

	if (-1 == fchmod (fd, 0644))
	{
		fprintf (stderr, "Failed to chmof pid file ('%s')\n", pid_file);
		perror ("fchmod");
		exit (EXIT_FAILURE);
	}

	if (NULL == (fp_pid = fdopen (fd, "wt")))
	{
		perror ("fdopen");
		close (fd);
		exit (EXIT_FAILURE);
	}

	fprintf (fp_pid, "%d\n", getpid());
	fclose (fp_pid);
	fp_pid = NULL;
	fd = -1;
}

void	wrapper_snmp_read (fd_set *fdset)
{
	snmp_read (fdset);
}

void	wrapper_snmp_timeout (void)
{
	snmp_timeout ();
}

// Returns 0 on success, -1 on error.
int	do_main_loop (void)
{
	fd_set		set;
	struct timeval	timeout = {0};
	int		max_fd = 0;
	int		block = 0;
	int		r = 0;
	struct device	*dev = NULL;

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	FD_ZERO (&set);

	for (dev = g_pDeviceList; dev; dev = dev->next_device)
	{
		if (dev->pcap)
		{
			FD_SET (dev->pcap_fd, &set);
			max_fd = (dev->pcap_fd > max_fd) ? dev->pcap_fd : max_fd;
		}
	}

	if (do_snmp)
	{
		snmp_select_info (&max_fd, &set, &timeout, &block);
	}

	if (-1 == (r = select (max_fd + 1, &set, NULL, NULL, &timeout)))
	{
		if (EINTR == errno) return 0;

		perror ("select");
		return -1;
	}

	if (do_snmp)
	{
		if (r)
		{
			wrapper_snmp_read (&set);
		}
		else
		{
			wrapper_snmp_timeout ();
		}
	}

	for (dev = g_pDeviceList; dev; dev = dev->next_device)
	{
		if (dev->pcap && (FD_ISSET (dev->pcap_fd, &set)))
		{
			if (-1 == (r = pcap_dispatch (dev->pcap, 0, callback, (u_char*)dev)))
			{
				fprintf (stderr, "pcap_dispatch (%s) failed: %s\n", dev->dev_name, pcap_geterr (dev->pcap));
			}
		}
	}

	return 0;
}

void	run_main_loop (void)
{
// Multiplex capture devices until we fail or get SIGINT.
	while (!g_shutdown)
	{
		if (0 > do_main_loop())
		{
			break;
		}
	}
}

static const char usage_txt[] =
	"Usage: %s [opts]\n"
	"-c config file         (default = '%s')\n"
	"-u runas user          (default = '%s')\n"
	"-g runas group         (default = '%s')\n"
	"-p pid file            (default = '%s')\n"
	"-l log file		(default = '%s')\n"
	"-d become daemon       (default = no)\n"
	"-v verbose             (default = no)\n"
	"-f force               (default = no)\n"
	"-x disable snmp        (default = no)\n";

static void usage (const char *prog)
{
	fprintf (stderr, usage_txt, prog,
		DEFAULT_CONFIG_FILE,
		DEFAULT_RUNAS_USER,
		DEFAULT_RUNAS_GROUP,
		DEFAULT_PID_FILE,
		DEFAULT_LOG_FILE);
	exit (-1);
}

int	main (int argc, char *argv[])
{
	int		i = 0;
	int		fd = 0;
	struct device	*dev = NULL;
	char		errbuf[PCAP_ERRBUF_SIZE];
	struct passwd	*pwd = NULL;
	struct group	*grp = NULL;
	char		*endptr = NULL;

	while (-1 != (i = getopt (argc, argv, "xfvdu:g:p:c:l:")))
	{
		switch (i)
		{
			case 'c':
				config_file = optarg;
				break;

			case 'l':
				log_file = optarg;
				break;

			case 'v':
				verbose++;
				break;

			case 'd':
				_daemon++;
				break;

			case 'u':
				runas_user = optarg;
				break;

			case 'g':
				runas_group = optarg;
				break;

			case 'p':
				pid_file = optarg;
				break;

			case 'f':
				force++;
				break;

			case 'x':
				do_snmp = 0;
				break;

			case 'h':
			case '?':
				usage (argv[0]);
				break;
		}
	}

	if (!config_file)
	{
		fprintf (stderr, "You must specify a config file via '-c xxxx'\n");
		usage (argv[0]);
	}

	process_cfg_file (config_file);

// Resolve '-u' arg, if any.
	runas_uid = strtol (runas_user, &endptr, 10);		// Allow a numeric string?
	if (*endptr)
	{
		if (NULL == (pwd = getpwnam (runas_user)))
		{
			fprintf (stderr, "Unknown user account: '%s'.\n", runas_user);
			exit (EXIT_FAILURE);
		}
		runas_uid = pwd->pw_uid;
		runas_gid = pwd->pw_gid;
	}

	runas_gid = strtol (runas_group, &endptr, 10);
	if (*endptr)
	{
		if (NULL == (grp = getgrnam (runas_group)))
		{
			fprintf (stderr, "Unknown group: '%s'\n", runas_group);
			exit (EXIT_FAILURE);
		}
		runas_gid = grp->gr_gid;
	}

	if (getuid())
	{
		fprintf (stderr, "%s must be started as 'root'.\n", argv[0]);
		exit (EXIT_FAILURE);
	}

// If we are a daemon, enter daemon mode
	if (_daemon)
	{
// Step 1, have the parent exit immediately.
		if (fork()) { exit (0); }

// Step 2, create a new session group.
		setsid();

// Step 3, fork again, so that the session group leader can exit.
// Note: We will never be able to regain control of a terminal.
		if (fork()) { exit (0); }

// Step 4, do not keep a lock on the 'cwd'.
		if (chdir ("/")) { exit (0); }

// Step 5, deny 'other' access to any files that we create (by default).
		umask(007);

// Step 6, close all descriptors that belonged to our parent.
		close(0);
		close(1);
		close(2);

// Step 7, reopen those descriptors for our own use.
		fd = open("/dev/null", O_RDONLY);
		assert(fd == 0);

		fd = open(log_file, O_WRONLY | O_APPEND | O_CREAT, 0644);
		assert(fd == 1);
//		fchmod(fd, 0644);

		fd = dup2(1, 2);
		assert(fd == 2);
	}
	else
	{
		umask(007);
	}

	if (verbose)
	{
		printf ("%s pid = %d\n", argv[0], getpid());
	}

	for (i = 0; sig_list[i]; i++)
	{
		signal (sig_list[i], handler_shutdown);
	}
	signal (SIGUSR1, handler_usr1);

// If we are a daemon our PID has changed twice since when we were spawned.
// Create the PID file.

	if (!force && pid_file)
	{
		create_pid_file ();
	}

// Open capture files before we surrender our privlidges.
	for (dev = g_pDeviceList; dev; dev = dev->next_device)
	{
		if (!dev->dev_name) continue;

		if (NULL == (dev->pcap = pcap_open_live (dev->dev_name, BUFSIZ, 1, pcap_timeout, errbuf)))
		{
			fprintf (stderr, "pcap_open_live (%s) failed.\n", dev->dev_name);
			dev->pcap = NULL;
			dev->pcap_fd = 0;
			continue;
		}

		if (-1 == (dev->pcap_fd = pcap_get_selectable_fd (dev->pcap)))
		{
			fprintf (stderr, "pcap_get_selectable_fd (%s) failed.\n", dev->dev_name);
			pcap_close (dev->pcap);
			dev->pcap = NULL;
			dev->pcap_fd = 0;
			continue;
		}
	}

// Connect to SNMP daemon
// See http://www.net-snmp.org/wiki/index.php/TUT:Writing_a_Subagent
	if (do_snmp)
	{
		setenv ("SNMP_PERSISTENT_FILE", snmp_persistent_file, 1);

		snmp_enable_stderrlog ();
		netsnmp_ds_set_boolean (NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
		init_agent (daemon_name);
		init_pcapSnmpMonitorMIB ();
		init_snmp (daemon_name);
	}

// Change group first (can't change it after changing user).
	if (runas_gid)
	{
		if (-1 == setgid (runas_gid))
		{
			fprintf (stderr, "setgid (%d) failed.\n", runas_gid);
			perror ("setgid");
			unlink (pid_file);
			exit (EXIT_FAILURE);
		}
	}

	if (runas_uid)
	{
		if (-1 == setuid (runas_uid))
		{
			fprintf (stderr, "setuid (%d) failed.\n", runas_uid);
			perror ("setuid");
			unlink (pid_file);
			exit (EXIT_FAILURE);
		}
	}

	run_main_loop();

	if (verbose)
	{
		printf ("exiting...\n");
	}

	if (do_snmp)
	{
		snmp_shutdown (daemon_name);
	}

	for (dev = g_pDeviceList; dev; dev = dev->next_device)
	{
		if (dev->pcap)
		{
			pcap_close (dev->pcap);
		}
	}

	if (-1 == unlink (pid_file))
	{
		perror ("unlink");
	}

	return 0;
}
