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
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "command_parse.h"
#include "state_machine.h"
#include "common/defines.h"
#include "global_var.h"

#define IS_ACK(command)		((command) != NULL && \
							strlen(command) == 3 && \
							strncmp((command), "ACK", 3) == 0)

#define IS_NACK(command)	((command) != NULL && \
							strlen(command) == 4 && \
							strncmp((command), "NACK", 4) == 0)

// TODO: Move to command_parse.c
// TODO: Check for ';' with '\' before (and for double '\')
// NULL: not enough data to determine length
// other: command
char * get_command(char * ringbuffer, int ringbuffer_len)
{
	char * command = NULL;
	char * newpos;
	int pos = 0;
	size_t length;

	for (pos = 0 ; ringbuffer[pos] != 0 && ringbuffer[pos] != ';'; pos++ ) {

	}

	if (ringbuffer[pos] == ';') {

		// Copy content of the command
		command = (char*) malloc(sizeof(char) * (pos + 1));
		strncpy(command, ringbuffer, pos);
		command[pos] = 0;

		// Remove that from the ringbuffer
		newpos = ringbuffer + pos + 1;
		length =  strlen(newpos);
		memmove(ringbuffer, newpos, length);
		memset(ringbuffer + length, 0, ringbuffer_len - length);
	}

#ifdef DEBUG
	if (command == NULL) {
		fprintf(stderr, "No command.\n");
	} else {
		fprintf(stderr, "Command <%s>.\n", command);
	}
#endif

	return command;
}

int parse_rpcap_command(char * command, char * host)
{
	int item, pch_len, ret;
	char * pch;
	struct rpcap_link * rlp;

	if (host == NULL || command == NULL) {
		return EXIT_FAILURE;
	}

	rlp = init_new_rpcap_link();

	// TODO: Give host
	rlp->host = (char *)calloc(1, (strlen(host) + 1) * sizeof(char));
	strcpy(rlp->host, host);

	pch = strtok(command, " ");
	for (item = 0; pch != NULL; item++) {
		// Make sure it is not empty because it cannot
		pch_len = strlen(pch);
		if (pch_len == 0) {
			return EXIT_FAILURE;
		}

#define COMPARE_PCH_LEN(str_compare, len) (pch_len == (len) && strncmp(pch, (str_compare), (len)) == 0)

		switch (item) {
			case 0: // RPCAP type
				rlp->encrypted = rlp->compressed = 0;

				if (COMPARE_PCH_LEN("ECRPCAP", 7)) {
					rlp->encrypted = rlp->compressed = 1;
				} else if (COMPARE_PCH_LEN("ERPCAP", 6)) {
					rlp->encrypted = 1;
				} else if (!COMPARE_PCH_LEN("RPCAP", 5)) {
					// Invalid command, NACK
					free_rpcap_link(&rlp);
					return EXIT_FAILURE;
				}
				break;
			case 1: // Kind of data to receive

				if (COMPARE_PCH_LEN("EVERYTHING", 10)) {
					rlp->data_type = DATA_TYPE_EVERYTHING;
				} else if (COMPARE_PCH_LEN("NOPAYLOAD", 9)) {
					rlp->data_type = DATA_TYPE_NOPAYLOAD;
				} else if (COMPARE_PCH_LEN("NODATA", 6)) {
					rlp->data_type = DATA_TYPE_NODATA;
				} else {
					free_rpcap_link(&rlp);
					return EXIT_FAILURE;
				}
				break;
			case 2: // Active/Passive
				rlp->pasv = COMPARE_PCH_LEN("PASV", 4);
				if (!rlp->pasv && !COMPARE_PCH_LEN("ACTIVE", 6)) {
					free_rpcap_link(&rlp);
					return EXIT_FAILURE;
				}
				break;
			case 3: // Port (if active)
				if (rlp->pasv) {
					free_rpcap_link(&rlp);
					return EXIT_FAILURE;
				}
				rlp->port = atoi(pch);

				if (!CHECK_SOCKET_PORT(rlp->port)) {
					free_rpcap_link(&rlp);
					return EXIT_FAILURE;
				}
				break;
			default:
				free_rpcap_link(&rlp);
				return EXIT_FAILURE;
				break;
		}

		pch = strtok (NULL, " ");
	}
#undef COMPARE_PCH_LEN

	// Connect to the server (in the background)
	ret = start_rpcap(rlp);
	free_rpcap_link(&rlp);

	return ret;
}

char * parse_command(char * command, int * state)
{
	int unknown_command = 1;
	char * ret = NULL;

	if (state == NULL) {
		return NULL;
	}
#ifdef DEBUG
	fprintf(stderr, "[*] State: %d.\n", *state);
	if (command != NULL) {
		fprintf(stderr, "[*] Command <%s>.\n", command);
	}
#endif

	if (*state == STATE_CONNECTED && command == NULL) {
		_protocol_version = MAX_SUPPORTED_PROTOCOL_VERSION;
		return get_supported_version(_protocol_version);
	}

	if (IS_ACK(command)) {
		unknown_command = 0;
		switch(*state) {
			case STATE_CONNECTED:
				// Version sent and approved, send login
				ret = (char *)calloc(1, (5 + 1 + strlen(_login) + 1 + 1)* sizeof(char));
#ifdef DEBUG
	fprintf(stderr, "[*] Sending login.\n");
#endif
				sprintf(ret, "LOGIN %s;", _login);
				*state = STATE_VERSION;
				break;
			case STATE_VERSION:
				// Login sent, send PASS
				ret = (char *)calloc(1, (4 + 1 + strlen(_pass) + 1 + 1)* sizeof(char));
#ifdef DEBUG
	fprintf(stderr, "[*] Sending password.\n");
#endif
				sprintf(ret, "PASS %s;", _pass);
				*state = STATE_LOGIN;
				break;
			case STATE_LOGIN:
				// pass sent, send GET_CONFIG
				ret = (char *)calloc(1, (11 + 1 )* sizeof(char));
#ifdef DEBUG
	fprintf(stderr, "[*] Sending GET_CONFIG.\n");
#endif
				strcpy(ret, "GET_CONFIG;");
				*state = STATE_LOGGED_IN;
				break;
			default:
				break;
		}
	} else if (IS_NACK(command)) {
		// Log and disconnect
		unknown_command = 0;
		switch(*state) {
			case STATE_CONNECTED:
				// Version sent and approved, send login
				// Try a lower version
				if (_protocol_version == MIN_SUPPORTED_PROTOCOL_VERSION) {
#ifdef DEBUG
					fprintf(stderr, "Protocol version %u unsupported, are you sure it's our server? Disconnecting.\n", MIN_SUPPORTED_PROTOCOL_VERSION);
#endif
					*state = STATE_NOT_CONNECTED;
					return NULL;
				} else {
#ifdef DEBUG
					fprintf(stderr, "Protocol version %u unsupported, trying a lower version.\n", _protocol_version);
#endif
					--_protocol_version;
				}
				ret = get_supported_version(_protocol_version);
				break;
			case STATE_VERSION:
				// WTF, NACK on login, is it really our server?
#ifdef DEBUG
				fprintf(stderr, "WTF, NACK on LOGIN, are you sure it's our server? Disconnecting.\n");
#endif
				return NULL;
				break;
			case STATE_LOGIN:
				// NACK on pass: Disconnect and abort
				return NULL;
				break;
			default:
				break;
		}
	} else if (strlen(command) > 5 && strstr(command, "RPCAP ")) {

		// TODO: Fix that shit (I mean use common/client)
		if (parse_rpcap_command(command, _host) == EXIT_SUCCESS) {
			unknown_command = 0;
			ret = (char *)calloc(1, (3 + 1 + 1)* sizeof(char));
			strcpy(ret, "ACK;");
		}
	}

	if (unknown_command) {
		fprintf(stderr, "No freakin' idea what the command <%s> means.\n", command);
		ret = (char *)calloc(1, (4 + 1 + 1)* sizeof(char));
		strcpy(ret, "NACK;");
	}

	return ret;
}

char * get_supported_version(unsigned int version)
{
	char * ret = (char *)calloc(1, (11 + (int)log(version)) * sizeof(char));
	sprintf(ret, "VERSION %u;", version);
	return ret;
}
