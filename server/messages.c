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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "messages.h"
#include "common/defines.h"

void init_message_thread()
{
	_message_thread = PTHREAD_NULL;
	pthread_mutex_init(&_message_list_mutex, NULL);
	_message_list = NULL;
}

void free_global_memory_message()
{
	struct message_details * cur, *prev;

	for (cur = _message_list; cur != NULL;) {
		prev = cur;
		cur = cur->next;
		FREE_AND_NULLIFY(prev->data);
		FREE_AND_NULLIFY(prev->message);
		free(prev);
	}

	pthread_mutex_destroy(&_message_list_mutex);
}

int add_message_to_queue(int message_type, unsigned char * data, unsigned char force_display, char * message)
{
	struct message_details * msg, * cur;

	if (STRING_IS_NULL_OR_EMPTY(message)) {
		return EXIT_FAILURE;
	}

	msg = (struct message_details *)malloc(sizeof(struct message_details));
	msg->message = message;
	msg->data = data;
	msg->message_type = message_type;
	msg->next = NULL;
	msg->displayed = 0;
	msg->force_display = force_display;
	msg->id = 0; // Not used yet
	time(&(msg->time));

	pthread_mutex_lock(&_message_list_mutex);

	// Append it to the list
	if (_message_list == NULL) {
		_message_list = msg;
	} else {
		for (cur = _message_list; cur->next != NULL; cur = cur->next);
		cur->next = msg;
	}

	pthread_mutex_unlock(&_message_list_mutex);

	return EXIT_SUCCESS;
}

int start_message_thread()
{
	int thread_created;

	if (_message_thread != PTHREAD_NULL) {
		return EXIT_SUCCESS;
	}

	thread_created = pthread_create(&_message_thread, NULL, (void*)&message_thread, NULL);
	if (thread_created != 0) {
		fprintf(stderr,"ERROR, failed to create message thread.\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int has_message_been_displayed_already(struct message_details * msg)
{
	struct message_details * cur;
	if (msg == NULL) {
		return 0;
	}

	if (msg->displayed) {
		return 1;
	}

	for (cur = _message_list; cur != NULL && cur != msg; cur = cur->next) {
		if (cur->displayed && strcmp(msg->message, cur->message) == 0) {
			return 1;
		}
	}

	return 0;
}

int message_thread(void * data)
{
	struct message_details * last, * cur, * to_keep, * prev, *next;
	time_t cur_time;
	char * time_str;

	last = NULL;

	while (!_stop_threads) {
		time(&cur_time);
		to_keep = NULL;

		if (last == NULL) {
			last = _message_list;
		}

		if (last) {
			pthread_mutex_lock(&_message_list_mutex);
			// Check for new messages and display them (make sure it hasn't been displayed in the last X seconds).
			for (cur = last; cur != NULL; cur = cur->next) {

				// Check if that message has been displayed (or must be displayed)
				if (cur->force_display || has_message_been_displayed_already(cur) == 0) {

					// Display this message
					time_str = ctime(&(cur->time));
					fprintf(stderr, "%s - %7s - %s\n", time_str,
														MESSAGE_TYPE_TO_STRING(cur->message_type),
														cur->message);
					free(time_str);

					// And update its status
					cur->displayed = 1;

					last = cur;
				}
			}

			// Clear messages older than X seconds
			for (cur = _message_list; cur != NULL; cur = cur->next) {
				if (difftime(cur_time, cur->time) < TIME_IN_SEC_BEFORE_MESSAGE_REDISPLAY) {
					to_keep = cur;
					break;
				}
			}

			// Clear messages
			for (cur = _message_list; cur != NULL && to_keep != cur;) {
				prev = cur;
				cur = cur->next;
				FREE_AND_NULLIFY(prev->data);
				FREE_AND_NULLIFY(prev->message);
				free(prev);
			}
			_message_list = to_keep;

			// Clear all undisplayed messages
			prev = NULL;
			next = NULL;
			for (cur = _message_list; cur != NULL;) {
				next = cur->next;
				if (cur->displayed == 0) {
					if (prev == NULL) {
						_message_list = next;
					} else {
						prev->next = next;
					}

					FREE_AND_NULLIFY(cur->data);
					FREE_AND_NULLIFY(cur->message);
					free(cur);
				} else {
					prev = cur;
				}
				cur = next;
			}

			pthread_mutex_unlock(&_message_list_mutex);

		}

		// Sleep a little
		usleep(100000);
	}

	return EXIT_SUCCESS;
}
