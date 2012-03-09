/*
 * OpenWIPS-ng sensor.
 * Copyright (C) 2011 Thomas d'Otreppe de Bouvette
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *      Author: Thomas d'Otreppe de Bouvette
 */
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "common/pcap.h"
#include "common/defines.h"
#include "packet_capture.h"
#include "global_var.h"

int is_valid_iface(const char * dev)
{
	if (dev == NULL) {
		return 0;
	}
#ifndef __CYGWIN__
	int ifaceLen = strlen(dev);
	return ifaceLen >= 3 && isdigit(dev[ifaceLen - 1]);
#else
	return strstr(dev, "airpcap") != NULL;
#endif
}

inline int inject(pcap_t * handle, const void * packet, size_t size)
{
	return pcap_inject(handle, packet, size);
}

// Also call this function when starting remote pcap (only is _pcap_thread == PTHREAD_NULL)
int start_monitor_thread(struct client_params * params)
{
	int thread_created;
	if (params == NULL) {
		return EXIT_FAILURE;
	}

	if (_pcap_thread != PTHREAD_NULL) {
		return EXIT_SUCCESS;
	}

	thread_created = pthread_create(&_pcap_thread, NULL, (void*)&monitor, params);
	if (thread_created != 0) {
		fprintf(stderr,"ERROR, failed to create packet capture (on %s) thread\n", _mon_iface);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

// TODO: Add detection when the interface gets down or disappear.
// TODO: Only start capture when we start RPCAP (instead of doing it at startup)
int monitor(void * data)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * handle;
	struct pcap_pkthdr * packet_header;
	struct pcap_packet * whole_packet, *to_inject;
	const u_char * packet;
	int capture_success, can_set_monitor_mode;
	struct client_params * params;
	struct pcap_file_header pfh;

	_pcap_header = NULL;

	params =  (struct client_params *)data;
	if (data == NULL) {
		fprintf(stderr, "Monitor mode failure due to NULL param.\n");
	}

	handle = pcap_create(_mon_iface, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Failed to create live capture handle on %s: %s\n", _mon_iface, errbuf);
		return EXIT_FAILURE;
	}

	// If we can set monitor mode, do it
	can_set_monitor_mode = (pcap_can_set_rfmon(handle) == 1);
	if (can_set_monitor_mode) {
		printf("Enabling monitor mode on interface %s\n", _mon_iface);
		if (pcap_set_rfmon(handle, 1)) {
			fprintf(stderr, "Failed to start monitor mode on %s\n", _mon_iface);
			pcap_close(handle);
			return EXIT_FAILURE;
		}
	} else {
		printf("Will not set monitor mode on %s.\n", _mon_iface);
	}

	if (pcap_activate(handle)) {
		fprintf(stderr, "Failed to activate interface %s\n", _mon_iface);
		pcap_close(handle);
		return EXIT_FAILURE;
	}

	printf("Starting live capture on interface %s\n", _mon_iface);

	handle = pcap_open_live(_mon_iface, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Failed to open %s: %s\n", _mon_iface, errbuf);
		return EXIT_FAILURE;
	}

#if defined(__APPLE__) && defined(__MACH__)
	printf("Forcing Linktype to radiotap (DLT_IEEE802_11_RADIO) for OSX.\n");
	if (pcap_set_datalink(handle, LINKTYPE_RADIOTAP) == -1) {
		fprintf(stderr, "Failed to set link type to radiotap (DLT_IEEE802_11_RADIO).\n");
		return EXIT_FAILURE;
	}
#endif

	// Get pcap file header
	pfh = get_packet_file_header(pcap_datalink(handle));
	_pcap_header = &pfh;

	// Check if link type is supported
	if (!is_valid_linktype(pfh.linktype)) {
		fprintf(stderr, "Unsupported link type: %d\n", pfh.linktype);
		pcap_close(handle);
		return EXIT_FAILURE;
	}

	#ifdef DEBUG
		int debug_ret = createPcapFile(DUMP_FILENAME, pcap_datalink(handle));
	#endif

	while (params->client->connected && !params->client->stop_thread)
	{
		// Check if there are packets to send and send them
		if (params->received_packets->nb_packet > 0) {
			to_inject = get_packets(1, &(params->received_packets));
			if (to_inject) {
				inject(handle, to_inject->data, to_inject->header.cap_len);
				free_pcap_packet(&to_inject, 1);
			}
		}

		capture_success = pcap_next_ex(handle, &packet_header, &packet);

		// Handle errors
		if (capture_success != 1) {
			if (capture_success == ERROR_PCAP_OEF) {
				fprintf(stderr, "Capturing from a file, EOF.\n");
				break; // End capture
			}
			if (capture_success == ERROR_PCAP_PACKET_READ_ERROR) {
				fprintf(stderr, "Error occurred while reading the packet: %s\n", pcap_geterr(handle));
			} if (capture_success == ERROR_PCAP_TIMEOUT) {
				fprintf(stderr, "Timeout occurred while reading the packet\n");
			} else {
				fprintf(stderr, "Unknown pcap_next_ex() error: %i\n", capture_success);
			}

			// Make sure it won't consume 100% of the CPU in case of error
			usleep(500);
			continue;
		}

		#ifdef DEBUG
			debug_ret = append_packet_tofile(DUMP_FILENAME, packet_header, packet);
		#endif

		// Add packet to the queue of packets to send
		whole_packet = init_new_pcap_packet();
		whole_packet->header.cap_len = packet_header->caplen;
		whole_packet->header.orig_len = packet_header->len;
		whole_packet->header.ts_sec = packet_header->ts.tv_sec;
		whole_packet->header.ts_usec = packet_header->ts.tv_usec;
		whole_packet->data = (unsigned char *)malloc((packet_header->caplen) * sizeof(unsigned char));
		memcpy(whole_packet->data, packet, packet_header->caplen);
		add_packet_to_list(whole_packet, &(params->to_send_packets));
		//free_pcap_packet(&whole_packet); // Do not free packet (since the function doesn't make a copy to save some CPU cycles)

	}

#ifdef DEBUG
	fprintf(stderr, "monitor() thread finished.\n");
#endif

	pcap_close(handle);
	_pcap_header = NULL; // Don't free
	_pcap_thread = PTHREAD_NULL;

	return EXIT_SUCCESS;
}
