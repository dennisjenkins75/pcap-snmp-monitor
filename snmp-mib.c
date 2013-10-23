/*
	Copyright 2013, iStream Financial Services, Inc.
	Author, Dennis Jenkins (dennis.jenkins.75 (at) gmail.com)
	Published with permission of iStream Financial Services, Inc.

	This software is licensed under the GPL v2.
*/

// http://svn.wirelessleiden.nl/svn/node-config/other/80211MIB/code/agent/if80211Table.c
// http://www.net-snmp.org/wiki/index.php/TUT:Writing_a_Subagent
// https://svn.ntop.org/svn/ntop/tags/ntop_3_1/ntop/plugins/snmpPlugin.c

#include "pcap-snmp-monitor.h"

netsnmp_variable_list* pcapFilterTable_getFirst (
	void **loop_context,
	void **data_context,
	netsnmp_variable_list *put_index_data,
	netsnmp_iterator_info *mydata
)
{
	struct device *d = NULL;
	struct filter *f = NULL;

	*loop_context = NULL;
	*data_context = NULL;

// Find first valid filter within valid worker.
	for (d = g_pDeviceList; d; d = d->next_device)
	{
		if (!d->pcap) continue;
		if (!d->first_filter) continue;

		f = d->first_filter;
		*loop_context = (void*)f;
		*data_context = (void*)f;
		snmp_set_var_value (put_index_data, (u_char*) &f->index, sizeof(f->index));
		return put_index_data;
	}

	return NULL;
}

netsnmp_variable_list* pcapFilterTable_getNext (
	void **loop_context,
	void **data_context,
	netsnmp_variable_list *put_index_data,
	netsnmp_iterator_info *mydata
)
{
	struct device *d = NULL;
	struct filter *f = NULL;

	if (!loop_context) return NULL;		// Error.

	f = *(struct filter**)loop_context;
	if (!f) return NULL;			// Error.

	if (f->next_filter)
	{
		f = f->next_filter;
		*loop_context = (void*)f;
		*data_context = (void*)f;
		snmp_set_var_value (put_index_data, (u_char*) &f->index, sizeof(f->index));
		return put_index_data;
	}

	for (d = f->parent_device->next_device; d; d = d->next_device)
	{
		if (!d->pcap) continue;
		if (!d->first_filter) continue;

		f = d->first_filter;
		*loop_context = (void*)f;
		*data_context = (void*)f;
		snmp_set_var_value (put_index_data, (u_char*) &f->index, sizeof(f->index));
		return put_index_data;
	}

	return NULL;
}

void netsnmp_set_var_counter64 (netsnmp_variable_list *var, u_int64_t *val)
{
	struct counter64 val64;

	val64.high = *val >> 32;
	val64.low = *val & 0xffffffff;

	snmp_set_var_typed_value(var, ASN_COUNTER64, (u_char *)&val64, sizeof(val64));
}

void netsnmp_set_var_gauge (netsnmp_variable_list *var, int val32)
{
	snmp_set_var_typed_value(var, ASN_GAUGE, (u_char *)&val32, sizeof(val32));
}

void netsnmp_set_var_string (netsnmp_variable_list *var, const char *str)
{
	snmp_set_var_typed_value (var, ASN_OCTET_STR, (u_char *)str, strlen (str));
}

/** handles requests for the pcapFilterTable table */
int pcapFilterTable_handler (
	netsnmp_mib_handler		*handler,
	netsnmp_handler_registration	*reginfo,
	netsnmp_agent_request_info	*reqinfo,
	netsnmp_request_info		*requests
)
{
	netsnmp_request_info		*request;
	netsnmp_table_request_info	*table_info;
	netsnmp_variable_list		*var = NULL;
	struct filter			*filter = NULL;

	for (request = requests; request; request = request->next)
	{
		if (request->processed) continue;

		if (NULL == (filter = (struct filter*) netsnmp_extract_iterator_context (request)))
		{
			netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
			continue;
		}

		if (NULL == (table_info = netsnmp_extract_table_info (request)))
		{
			continue;
		}

/*		// Sanity checking.
		if (*table_info->indexes->val.integer != *index)
		{
			snmp_log (LOG_ERR, "pcapFilterTable_handler(): very odd mismatch of indicies (%ld, %ld).\n",
				*table_info->indexes->val.integer, *index);
			continue;
		}
*/
		var = request->requestvb;		// caching for brevity.

		if (MODE_GET != reqinfo->mode)
		{
			snmp_log (LOG_ERR, "pcapFilterTable_handler(), unsupported mode '%d'\n", reqinfo->mode);
			continue;
		}

//		fprintf (stderr, "snmp GET for %s, %d\n", filter->name, table_info->colnum);

		struct device *device = filter->parent_device;	// For brevity.

		switch (table_info->colnum)
		{
			case COLUMN_IFDESCR:
				netsnmp_set_var_string (var, device->dev_name);
				break;

			case COLUMN_FLTDESCR:
				netsnmp_set_var_string (var, filter->name);
				break;

			case COLUMN_FLTBPF:
				netsnmp_set_var_string (var, filter->bpf_text);
				break;

			case COLUMN_FLTPACKETS:
				netsnmp_set_var_counter64 (var, &(filter->packets));
				break;

			case COLUMN_FLTBYTES:
				netsnmp_set_var_counter64 (var, &(filter->bytes));
				break;

			case COLUMN_FLTTERMINAL:
				netsnmp_set_var_gauge (var, filter->terminal);
				break;

			default:
				netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
				break;
		}
	}

	return SNMP_ERR_NOERROR;
}

/** Initialize the pcapFilterTable table by defining its contents and how it's structured */
void	initialize_table_pcapFilterTable(void)
{
	static oid pcapFilterTable_oid[] = {1,3,6,1,4,1,8072,2,3000,2,1};
	netsnmp_handler_registration    *my_handler = NULL;
	netsnmp_table_registration_info *table_info = NULL;
	netsnmp_iterator_info *iinfo = NULL;

	table_info = SNMP_MALLOC_TYPEDEF (netsnmp_table_registration_info);
	iinfo = SNMP_MALLOC_TYPEDEF (netsnmp_iterator_info);

	my_handler = netsnmp_create_handler_registration (
		"pcapFilterTable",
		pcapFilterTable_handler,
		pcapFilterTable_oid,
		OID_LENGTH (pcapFilterTable_oid),
		HANDLER_CAN_RONLY );

	if (!my_handler || !table_info || !iinfo) return;

	netsnmp_table_helper_add_indexes (table_info, ASN_INTEGER, 0);

	table_info->min_column = COLUMN_IFDESCR;
	table_info->max_column = COLUMN_FLTTERMINAL;

	iinfo->get_first_data_point = pcapFilterTable_getFirst;
	iinfo->get_next_data_point = pcapFilterTable_getNext;
	iinfo->table_reginfo = table_info;

	netsnmp_register_table_iterator (my_handler, iinfo);
}

void	init_pcapSnmpMonitorMIB (void)
{
	initialize_table_pcapFilterTable ();
}
