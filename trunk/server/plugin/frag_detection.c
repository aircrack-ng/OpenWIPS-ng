/*
 * OpenWIPS-ng server plugin: Fragmentation detection.
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
#include "frame_plugin_header.h"

// Need a struct similar to replay + implement fragment_nr + more_frag in frame

void * init_plugin(char * config_line, int version)
{
	unsigned int * nb_frames = (unsigned int*)malloc(sizeof(unsigned int));
	*nb_frames = 1; // By default 1 frame is enough

	if (config_line) {
		*nb_frames = atoi(config_line);
		if (*nb_frames == 0) {
			*nb_frames = 1;
		}
	}

	return nb_frames;
}

void free_memory_and_unload(void * data)
{
	if (data) {
		free(data);
	}
}

char plugin_type(void)
{
	return 'F';
}

int min_supported_version()
{
	return 100;
}

int max_supported_version()
{
	return 0;
}

char * init_text(void * config)
{
	char * ret = (char *)calloc(1, 100 * sizeof(char));
	if (config) {
		sprintf(ret, "Fragmentation attack detection (with %u frames) v1.0",
				*((unsigned int *)config));
	} else {
		strcpy(ret, "Fragmentation attack detection v1.0");
	}

	return ret;
}

int static_frame_type()
{
	// It should only be data frames with data but there can be an idiot out there to try another kind of frame
	return -1;
}

int static_frame_subtype()
{
	return -1;
}

int need_all_frames()
{
	return 0;
}

int is_single_frame_attack()
{
	// No because it depends on the config
	return 0;
}

int require_packet_parsed()
{
	return 1;
}

int can_use_frame(struct pcap_packet * packet, void * config)
{
	if (packet == NULL || config == NULL) {
		return 0;
	}

	return 1;
}

int analyze(struct pcap_packet * packet, void * config)
{
	if (packet == NULL || packet->info == NULL || config == NULL) {
		return 0;
	}

	//packet->info->fragmentation
	return 0;
}

int nb_frames_before_analyzing(void * config)
{
	return (config) ? ((int) (*((unsigned int *)config))) : 1;
}

int time_ms_before_analyzing(void * config)
{
	if (config) { }
	return -1;
}

int is_attacked(struct pcap_packet * packet_list, void * config)
{
	return 0;
}

char * attack_details(void * config)
{
	return NULL;
}

unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth)
{
	if (deauth) {
		*deauth = 1;
	}

	return NULL;
}

void clear_attack(void * config)
{
	if (config) { }
}
