/*
 * OpenWIPS-ng server.
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

#ifndef PACKET_ANALYSIS_H_
#define PACKET_ANALYSIS_H_

#include <time.h>
#include <pthread.h>
#include "common/pcap.h"

#define FRAME_TYPE_TO_STRING(i) ((i) == 0) ? "Management" : ((i) == 1) ? "Control" : ((i) == 2) ? "Data" : "Invalid"

// TODO: Create struct and add time of the message and a thread to manage alerts and logging stuff
// Idea: struct message { time; message; data (if any); type (Log, ALERT, ANOMALY, ...); NEXT; }
// Store it in a SQLite database (simple design).
// Also have a function to know if a message has been displayed in the last X seconds (to avoid thousand of messages)
// TODO: Also clear pcap list when an attack has been detected.
char ** _message_list;
int _nb_messages;

struct message_details {
	uint32_t id; // Message ID
	time_t time; // Time of the message
	char * message; // Message itself
	unsigned char * data; // Any data (if useful)
	int message_type; // Message type (LOG, ALERT, ANOMALY, ...)
	struct message_details * next; // NEXT message
};

// TODO: Create software to create initialization, free, add, remove, remove_x_begin, ... because it is always the same operations.

#define MESSAGE_TYPE_NOT_SET	-1
#define MESSAGE_TYPE_REG_LOG	0
#define MESSAGE_TYPE_ALERT		1
#define MESSAGE_TYPE_ANOMALY	2

extern unsigned char ** _our_macs; // config.h
extern int _nb_macs; // config.h

// TODO: Make that kind of thing (thread start/kill system) generic and common (and probably use it for client and server)
//       Use like other stuff in common, fct pointers and put those variables in structs.

extern int _stop_threads;
extern struct packet_list * _receive_packet_list;

pthread_t _packet_analysis_thread;
volatile int _stop_packet_analysis_thread;
volatile int _packet_analysis_thread_stopped;

void init_packet_analysis();
void free_global_memory_packet_analysis();

int kill_packet_analysis_thread();

int start_packet_analysis_thread();
int is_one_of_our_mac(unsigned char * mac);
int packet_analysis_thread(void * data);

#endif /* PACKET_ANALYSIS_H_ */
