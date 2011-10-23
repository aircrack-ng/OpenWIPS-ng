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

#ifndef MESSAGES_H_
#define MESSAGES_H_

#include <stdint.h>
#include <pthread.h>
#include <time.h>

#define TIME_IN_SEC_BEFORE_MESSAGE_REDISPLAY	30

#define MESSAGE_TYPE_NOT_SET	-1
#define MESSAGE_TYPE_REG_LOG	0
#define MESSAGE_TYPE_ALERT		1
#define MESSAGE_TYPE_ANOMALY	2

#define MESSAGE_TYPE_TO_STRING(t) ((t) == MESSAGE_TYPE_REG_LOG) ? "LOG" : \
									((t) == MESSAGE_TYPE_ALERT) ? "ALERT" : \
									((t) == MESSAGE_TYPE_ANOMALY) ? "ANOMALY" : "UNKNOWN"

// TODO: Store it in a SQLite database (simple design).
struct message_details {
	uint32_t id; // Message ID (not used yet)
	time_t time; // Time of the message
	char * message; // Message itself
	unsigned char * data; // Any data (if useful)
	char message_type; // Message type (LOG, ALERT, ANOMALY, ...)
	unsigned char displayed; // Has the message been displayed
	unsigned char force_display; // Force display that message no matter what?
	struct message_details * next; // NEXT message
};

struct message_details * _message_list;
pthread_mutex_t _message_list_mutex;
pthread_t _message_thread;

void init_message_thread();
void free_global_memory_message();

int add_message_to_queue(int message_type, unsigned char * data, unsigned char force_display, char * message);
int start_message_thread();
int has_message_been_displayed_already(struct message_details * msg);
int message_thread(void * data);

extern int _stop_threads;

#endif /* MESSAGES_H_ */
