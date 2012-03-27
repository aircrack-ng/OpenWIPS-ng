/*
 * OpenWIPS-ng - common stuff.
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
#include <string.h>
#include "pcap.h"
#include "interface_control.h"
#include "defines.h"
#ifndef OSX
	#ifdef USE_LIBNL
		#include <netlink/version.h>
		#include <net/if.h>

		#if LIBNL_VER_NUM < LIBNL_VER(2,0)
			#error libnl80211 found but too old. Require libnl80211 2.0 or higher
		#endif
	#else
		#include <sys/types.h>
		#include <unistd.h>
		#include <sys/wait.h>
	#endif
#endif

struct rfmon * init_struct_rfmon() {
	struct rfmon * ret = (struct rfmon *)malloc(sizeof(struct rfmon));
	ret->handle = NULL;
	ret->interface = NULL;
	ret->link_type = 0;

	return ret;
}

int free_struct_rfmon(struct rfmon * elt) {
	if (elt->handle != NULL) {
		pcap_close(elt->handle);
	}
	FREE_AND_NULLIFY(elt->interface);
	free(elt);

	return EXIT_SUCCESS;
}

int set_monitor_mode_nl80211(char * interface, char * new_iface_name) {
	if (STRING_IS_NULL_OR_EMPTY(interface)) {
		fprintf(stderr, "set_monitor_mode_nl80211() - You must specify an interface.\n");
		return EXIT_FAILURE;
	}

	if (STRING_IS_NULL_OR_EMPTY(new_iface_name)) {
		fprintf(stderr, "set_monitor_mode_nl80211() - You must specify an interface name for the monitor mode interface.\n");
		return EXIT_FAILURE;
	}

#ifdef OSX
	return EXIT_FAILURE;
#elif defined(USE_LIBNL)
	struct nl80211_state nlstate;
	int iface_idx;

	// TODO: Check code from iw to see what airmon-ng calls
	if (nl80211_init(&nlstate)) {
		return EXIT_FAILURE;
	}

	iface_idx = if_nametoindex(interface);
	if (iface_idx == 0) {
		return EXIT_FAILURE;
	}

	// 1. NL80211_CMD_NEW_INTERFACE
	// 	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, name);
	//NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, type);


	// 2. Set monitor mode on new interface
	/* NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR); */

	return EXIT_FAILURE;
#else
	pid_t pid = fork();
	if (pid == 0) {
		close( 0 ); close( 1 ); close( 2 );
		execlp("iw", "iw", "dev", interface, "interface", "add", new_iface_name, "type", "monitor", NULL);
		return EXIT_FAILURE;
	} else {
		// Wait for child
		waitpid(pid, 0, 0);

		// Set the interface up
		if (set_interface_up(new_iface_name) == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
#endif
}

int set_interface_up(char * interface) {
	if (STRING_IS_NULL_OR_EMPTY(interface)) {
		fprintf(stderr, "set_interface_up() - Seriously, if you wanna set the interface up, you gotta have to specify one, I can't guess it, my crystal ball is broken.\n");
		return EXIT_FAILURE;
	}

	pid_t pid = fork();
	if (pid == 0) {
		close( 0 ); close( 1 ); close( 2 );
		execlp("ifconfig", "ifconfig", interface, "up", NULL);
		return EXIT_FAILURE;
	} else {
		// Wait for child
		waitpid(pid, 0, 0);
	}

	return EXIT_SUCCESS;
}

struct rfmon * enable_monitor_mode(char * interface, enum rfmon_action_enum action) {
	int can_set_monitor_mode;

	char errbuf[PCAP_ERRBUF_SIZE];
#ifndef OSX
	char * new_iface;
	const char * interface_name_pattern = "%smon"; // eg: wlan0mon
#endif
	struct rfmon * ret = init_struct_rfmon();

	if (STRING_IS_NULL_OR_EMPTY(interface)) {
		fprintf(stderr, "enable_monitor_mode() - You must specify an interface.\n");
		free_struct_rfmon(ret);
		return NULL;
	}

	// Make sure the interface is up
	set_interface_up(interface);

	printf("Starting live capture on interface %s\n", interface);

	// Try opening
	ret->handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
	if (ret->handle == NULL) {
		fprintf(stderr, "Failed to open %s: %s\n", interface, errbuf);
		free_struct_rfmon(ret);
		return NULL;
	}

#if defined(__APPLE__) && defined(__MACH__)
	printf("Forcing Linktype to radiotap (DLT_IEEE802_11_RADIO) for OSX.\n");
	if (pcap_set_datalink(ret->handle, LINKTYPE_RADIOTAP) == -1) {
		fprintf(stderr, "Failed to set link type to radiotap (DLT_IEEE802_11_RADIO).\n");
		free_struct_rfmon(ret);
		return NULL;
	}
#endif

	// Get pcap file header
	ret->link_type = pcap_datalink(ret->handle);

	// Check if link type is supported
	if (!is_valid_linktype(ret->link_type)) {
		fprintf(stderr, "Unsupported link type <%d> on <%s>\n", ret->link_type, interface);
		pcap_close(ret->handle);
		ret->handle = NULL;

		// Stuff to do in case of failure
		if (action == FIRST_CALL) {
			fprintf(stderr, "Not fatal, trying enabling monitor mode first\n");
			// Try setting monitor mode and recall this
			ret->handle = pcap_create(interface, errbuf);
			if (ret->handle == NULL) {
				fprintf(stderr, "Failed to create live capture handle on %s: %s\n", interface, errbuf);
				free_struct_rfmon(ret);
				return NULL;
			}

			// If we can set monitor mode, do it
			can_set_monitor_mode = (pcap_can_set_rfmon(ret->handle) == 1);
			if (can_set_monitor_mode) {
				printf("Enabling monitor mode on interface %s\n", interface);
				if (pcap_set_rfmon(ret->handle, 1)) {
					fprintf(stderr, "Failed to start monitor mode on %s\n", interface);
					free_struct_rfmon(ret);
					return NULL;
				}
			} else {
				printf("Will not set monitor mode on %s.\n", interface);
			}

			if (pcap_activate(ret->handle)) {
				fprintf(stderr, "Failed to activate interface %s: %s\n", interface, pcap_geterr(ret->handle));
				fprintf(stderr, "With mac80211 drivers, use a monitor mode interface created with 'iw' or 'airmon-ng'.\n");
				free_struct_rfmon(ret);
				return NULL;
			}

			// retry this
			free_struct_rfmon(ret);
			return enable_monitor_mode(interface, TRY_RFMON_NL80211);
		}

#ifndef OSX
		else if (action == TRY_RFMON_NL80211) {
			fprintf(stderr, "Not fatal, trying again using mac80211\n");
			// Use NL80211
			new_iface = (char *)calloc(1, strlen(interface) + strlen(interface_name_pattern));
			sprintf(new_iface, interface_name_pattern, interface, 0); // TODO: Detect existing interface and get rid of them
			if (set_monitor_mode_nl80211(interface, new_iface) == EXIT_SUCCESS) {

				// Retry this
				free_struct_rfmon(ret);
				ret = enable_monitor_mode(new_iface, DONT_TRY_AGAIN);
				free(new_iface);
				return ret;
			}

			free(new_iface);
		}
#endif
		free_struct_rfmon(ret);
		return NULL;
	}

	// Copy interface used
	ret->interface = (char *)calloc(1, strlen(interface) + 1);
	strcpy(ret->interface, interface);

	return ret;
}
