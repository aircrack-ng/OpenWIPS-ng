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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "common/defines.h"
#include "common/utils.h"
#include "plugins.h"

// TODO: Use the whole config (not only those 2 keys
int parse_our_mac_addresses()
{
	struct key_value * kv;
	char * pch;
	int item_nb;
	unsigned char * parsed_mac;

	// Parse list of our macs
	_nb_macs = 0;
	_our_macs = NULL;

	if (_config == NULL) {
		return EXIT_SUCCESS;
	}

	for (kv = _config; kv != NULL; kv = kv->next) {
		// key: allow_bssid and allow_client
		if ((strcmp(kv->key, "allow_bssid") == 0 ||
				strcmp(kv->key, "allow_client") == 0) &&
				!STRING_IS_NULL_OR_EMPTY(kv->value)) {

			pch = strtok(kv->value, " ");
			item_nb = 0;
			while (!STRING_IS_NULL_OR_EMPTY(pch)) {
				if (item_nb++) { // First item is the name of the group (currently ignored - TODO: Fix it)
					// Parse mac
					parsed_mac = parse_mac_from_string(pch);

					// If parsing failed, stop processing
					if (parsed_mac == NULL) {
						fprintf(stderr, "[*] Invalid mac address <%s>, fix your config.\n", pch);
						return EXIT_FAILURE;
					}

					// Add mac to the list
					if (_our_macs == NULL) {
						_our_macs = (unsigned char **)malloc(sizeof(unsigned char *));
					} else {
						_our_macs = (unsigned char **)realloc(_our_macs, (_nb_macs + 1) * sizeof(unsigned char *));
					}
					*(_our_macs + _nb_macs) = parsed_mac;
					++_nb_macs;
				}
				pch = strtok(NULL, " ");
			}
		}
	}

	return EXIT_SUCCESS;
}

int parse_plugins_options()
{
	// Based on the config load all plugins
	char * pch, *name, *path, *param, *init_text;
	int item;
	struct plugin_info * pi, *plugin_list;
	struct key_value * cur = _config;

	while (cur != NULL) {
		if (strcmp(cur->key, "plugin") == 0) {
			pch = strtok(cur->value, " ");
			name = NULL;
			path = NULL;
			for (item = 0; pch != NULL; ++item) {
				switch(item) {
					case 0:
						name = pch;
						break;
					case 1:
						path = pch;
						break;
					default:
						break;
				}
				pch = strtok(NULL, " ");
			}

			if (!name || !path) {
				fprintf(stderr, "ERROR: Incomplete plugin definition <%s>, fix your config file.\n", cur->value);
				return EXIT_FAILURE;
			}

			param = NULL;
			if (strlen(name) + strlen(path) + 2 < strlen(cur->value)) {
				// There are params
				param = cur->value + (strlen(name) + strlen(path) + 2);
			}

			// Load it
#ifdef DEBUG
			fprintf(stderr, "[*] Loading plugin <%s> named <%s> with those parameters: <%s>.\n", path, name, SHOW_TEXT_OR_NULL(param));
#endif
			// TODO: Load plugin parameters
			pi = load_plugin(name, path, param, 0);
			if (pi == NULL) {
				return EXIT_FAILURE;
			}

			// Display line inserted into log
			init_text =  pi->common_fct.init_text(pi->plugin_data);
			if (init_text != NULL) {
				fprintf(stderr, "[*] Plugin %s init: %s\n", name, init_text);
				FREE_AND_NULLIFY(init_text);
			}

			// Add it to the right list
			plugin_list = NULL;

			switch (pi->plugin_type) {
				case 'F':
					plugin_list = _plugin_frame;
					break;
				case 'D':
					plugin_list = _plugin_database;
					break;
				case 'A':
					plugin_list = _plugin_alert;
					break;
				case 'L':
					plugin_list = _plugin_logging;
					break;
				default:
					fprintf(stderr, "Unknown plugin type <%c>.\n", pi->plugin_type);
					unload_plugin(pi);
					free_plugin_info(&pi);
					return EXIT_FAILURE;
					break;
			}

			if (plugin_list != NULL) {
				while (plugin_list->next != NULL) {
					plugin_list = plugin_list->next;
				}
				plugin_list->next = pi;
			} else {
				switch (pi->plugin_type) {
					case 'F':
						_plugin_frame = pi;
						break;
					case 'D':
						_plugin_database = pi;
						break;
					case 'A':
						_plugin_alert = pi;
						break;
					case 'L':
						_plugin_logging = pi;
						break;
					default:
						break;
				}
			}

			fprintf(stderr, "[*] Loaded successfully plugin <%s>.\n", name);
		}

		cur = cur->next;
	}

	return EXIT_SUCCESS;
}

char * read_text_file_content(char * path)
{
	FILE * f;
	long int file_length, i;
	long int items_read;
	char * ret = NULL;

	if (path == NULL) {
		fprintf(stderr, "No path to the configuration file given.\n");
		return ret;
	}

	// Check if file exist
	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Configuration file does not exist.\n");
		return ret;
	}

	// Get length of the file then allocate the char * storing it
	fseek(f, 0, SEEK_END);
	file_length = ftell(f);

	if (file_length == 0) {
		fprintf(stderr, "Failed to read configuration file: file is empty.\n");
		fclose(f);
		return EXIT_SUCCESS;
	}

	fseek(f, 0, SEEK_SET);
	ret = (char *)calloc(1, (file_length + 2)* sizeof (char));
	items_read = fread(ret, file_length, 1, f);
	fclose(f);
	if (items_read != 1) {
		fprintf(stderr, "Failed to read configuration file.\n");
		free(ret);
		return EXIT_SUCCESS;
	}

	// Replace any occurence of NULL in the config file by a space.
	for (i = 0; i <= file_length; i++) {
		if (ret[i] == '\0') {
			ret[i] = ' ';
		}
	}

#ifdef DEBUG
	printf("Configuration file content:\n%s\n-----------------------\n", ret);
#endif

	return ret;
}

int parse_keyvalues(char * config_content)
{
	int line_begin, line_nb, skip_line, newpos;
	size_t file_length, i, value_len, key_len;
	char * line, *equal;
	struct key_value * cur_key_value;

	cur_key_value = NULL;
	_config = NULL;
	file_length = strlen(config_content);
	line = (char *)calloc(1, file_length * sizeof (char));

	line_begin = line_nb = 1;
	skip_line = newpos = 0;
	for (i = 0; i <= file_length; i++) {
		// Skip line if # at the beginning (or \r\n or \n)
		if (line_begin) {
			if (config_content[i] == '#') {
				skip_line = 1;
				line_begin = 0;
				continue;
			}
			else if (config_content[i] == '\r' || config_content[i] == '\n' || config_content[i] == ' ' || config_content[i] == '\t') {
				if (config_content[i] == '\n') {
					line_nb++;
				}
				continue;
			}

			line_begin = 0;
		} else if (config_content[i] == '\n' || i == file_length) {
			line_begin = 1;
			skip_line = 0;

			if (newpos != 0) {
				// Parse line
				equal = strchr(line, '=');
				if (equal == NULL) {
					fprintf(stderr, "Failed to parse configuration at line %d: %s\n", line_nb, line);
					free(line);

					// Don't free _config, let main() do it

					return EXIT_SUCCESS;
				}

				// Allocate memory
				if (_config == NULL) {
					cur_key_value = (struct key_value *)malloc(sizeof(struct key_value));
					_config = cur_key_value;
				} else {
					cur_key_value->next = (struct key_value *)malloc(sizeof(struct key_value));
					cur_key_value = cur_key_value->next;
				}

				// Init values
				cur_key_value->next = NULL;

				// Get Value
				value_len = strlen(equal + 1); // Skip equal char
				cur_key_value->value = (char *)calloc(1, value_len + 1 );
				strncpy(cur_key_value->value, equal + 1, value_len);

				// Get key
				key_len = strlen(line) - value_len - 1; // Skip equal char
				cur_key_value->key = (char *)calloc(1, key_len + 1 );
				strncpy(cur_key_value->key, line, key_len);


				// Reset line content
				memset(line, 0, strlen(line));
				newpos = 0;
			}

			line_nb++;
			continue;
		}

		if (skip_line || i == file_length) {
			continue;
		}

		// Copy it to temp
		line[newpos++] = config_content[i];
	}

	// Free memory that is not needed anymore
	free(line);

#ifdef DEBUG
	printf("Configuration file key/value pairs:\n");
	cur_key_value = _config;
	while (cur_key_value != NULL) {
		printf("%s -> %s\n", cur_key_value->key, cur_key_value->value);
		cur_key_value = cur_key_value->next;
	}
	printf("\n-----------------------\n");
#endif

	return EXIT_SUCCESS;
}

int read_conf_file(char * path)
{
	// Get content
	char * config_content = read_text_file_content(path);
	if (config_content == NULL) {
		return EXIT_FAILURE;
	}

	// Parse key/values pair
	if (parse_keyvalues(config_content) == EXIT_FAILURE) {
		free(config_content);
		return EXIT_FAILURE;
	}

	free(config_content);

	if (_config == NULL) {
		fprintf(stderr, "Do you really want to use it or just mess with me? You gonna need to put some stuff in the config file.\n");
		return EXIT_FAILURE;
	}

	//// Now analyze the content of each key/value pair

	// Parse users
	if (parse_all_userpass("user", &_userlist) == EXIT_FAILURE) {
		fprintf(stderr, "Config: failed to parse users.\n");
		return EXIT_FAILURE;
	}

	// Parse sensor users
	if (parse_all_userpass("sensor", &_sensorlist) == EXIT_FAILURE) {
		fprintf(stderr, "Config: failed to parse sensor users.\n");
		return EXIT_FAILURE;
	}

	if (parse_simple_options() == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}

	// Parse plugin options and load them
	if (parse_plugins_options() == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}

	// Parse list of allowed mac addresses
	if (parse_our_mac_addresses() == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int parse_simple_options()
{
	int port_min, port_max;
	char * pos;
	struct key_value * cur_key_value;

	// Set default options
	_disable_encryption = 0; // Encrypted by default
	_port = DEFAULT_SERVER_PORT;
	rpcap_init();

	// Note multiple definition of the same key can exist and thus the value in the end will be the one of the latest key
	for (cur_key_value = _config; cur_key_value != NULL; cur_key_value = cur_key_value->next) {
		if (strcmp(cur_key_value->key, "port") == 0) {
			_port = atoi(cur_key_value->value);
			if (_port < 1 || _port > 65535) {
				fprintf(stderr, "Invalid port <%s> in configuration. It must be between 1 and 65535.\n", cur_key_value->value);
				return EXIT_FAILURE;
			}
		} else if (strcmp(cur_key_value->key, "disable_encryption") == 0) {
			_disable_encryption = IS_TEXT_TRUE(cur_key_value->value);
		} else if (strcmp(cur_key_value->key, "rpcap_ports") == 0 && strlen(cur_key_value->value) > 0) {
			port_min = port_max = atoi(cur_key_value->value);
			pos = strchr(cur_key_value->value, ' ');
			if (pos != NULL) {
				port_max = atoi(pos + 1);
			}
			rpcap_add_ports(port_min, port_max);
		}
	}

#ifdef DEBUG
	printf("Simple configuration items:\n");
	printf("Port: %d\n", _port);
	printf("Disable encryption (sensor-server): %s\n", (_disable_encryption) ? "yes" : "no");
	printf("RPCAP port range: %d to %d\n", _rpcap_port_min, _rpcap_port_max);
	printf("-----------------------\n");
#endif

	return EXIT_SUCCESS;
}

int parse_all_userpass(const char * key, struct userpass ** upp)
{
#define NB_ELEM_USER_LINE	3
#define FREE_USERLINE		for (i = 0; i < NB_ELEM_USER_LINE; i++) { \
								if (userline[i] != NULL) { \
									free(userline[i]); \
								} \
								userline[i] = NULL; \
							}

	char * userline[NB_ELEM_USER_LINE];
	struct key_value * cur_key_value = _config;
	struct userpass * cur_userpass, * browse_up;
	char * pch;
	int cur_item, ip_present, i;

	*upp = NULL;

	if (cur_key_value == NULL) {
		fprintf(stderr, "Failed to analyze config: config is null.\n");
		return EXIT_FAILURE;
	}

	for(i = 0; i < NB_ELEM_USER_LINE; i++) {
		userline[i] = NULL;
	}

	while (cur_key_value != NULL) {

		if (cur_key_value->key != NULL && cur_key_value->value != NULL && strcmp(cur_key_value->key, key) == 0) {
			// split the line in 3 items
			cur_item = 0;
			pch = strtok (cur_key_value->value ," ");
			while (pch != NULL)
			{
				// Make sure it isn't invalid
				if (cur_item == NB_ELEM_USER_LINE) {
					fprintf(stderr, "Invalid number of items in line: %s = %s\n", cur_key_value->key, cur_key_value->value);
					FREE_USERLINE
					return EXIT_FAILURE;
				}

				userline[cur_item] = (char *)calloc(1, sizeof(char)* ( strlen(pch) + 1));
				strcpy(userline[cur_item++], pch);
				pch = strtok (NULL, " ");
			}

			if (cur_item != NB_ELEM_USER_LINE) {
				fprintf(stderr, "User line type unknown (invalid number of item: got %d, expected %d): %s\n", cur_item, NB_ELEM_USER_LINE, userline[1]);

				// Free memory
				FREE_USERLINE

				return EXIT_FAILURE;
			}

			// Parse it
			if (strcmp(userline[1], "PASS") && strcmp(userline[1], "IP")) {
				fprintf(stderr, "User line type unknown: %s\n", userline[1]);

				// Free memory
				FREE_USERLINE

				return EXIT_FAILURE;
			}

			// Search if the structure already exist for the user ...
			cur_userpass = *upp;
			while (cur_userpass != NULL) {
				if (strcmp(cur_userpass->user, userline[0]) == 0) {
					break;
				}
				cur_userpass = cur_userpass->next;
			}

			// TODO: Create functions add_user() in users.c/h

			// ... if it does not exist, create one and add it to the list
			if (cur_userpass == NULL) {
				cur_userpass = new_userpass();
				cur_userpass->user = (char *)calloc(1, sizeof(char) * (strlen(userline[0]) + 1));
				strcpy(cur_userpass->user,userline[0]);

				if (*upp == NULL) {
					*upp = cur_userpass;
				} else {
					browse_up = *upp;
					while (browse_up != NULL) {
						if (browse_up->next == NULL) {
							browse_up->next = cur_userpass;
							break;
						}

						browse_up = browse_up->next;
					}
				}
			}

			if (strcmp(userline[1], "PASS") == 0) { // Password definition
				if (cur_userpass->pass != NULL) {
					fprintf(stderr, "Password for user <%s> redefined, fix your config file.\n", userline[0]);
					// Free memory
					FREE_USERLINE
					return EXIT_FAILURE;
				}

				cur_userpass->pass = (char *)calloc(1, (strlen(userline[2]) + 1)*sizeof(char));
				strcpy(cur_userpass->pass, userline[2]);
			} else if (strcmp(userline[1], "IP") == 0) { // Allowed IP definition
				// Validate IP address
				if (is_ip_valid(userline[2]) == EXIT_FAILURE) {
					// Invalid IP
					fprintf(stderr,"IP <%s> is not a valid IPv4 or IPv6 address (user: %s).\n", userline[2], userline[0]);
					// Free memory
					FREE_USERLINE
					return EXIT_FAILURE;
				}

				ip_present = 0;
				// Search if the IP is not there already
				if (cur_userpass->allowed_ips != NULL && cur_userpass->nb_allowed_ips != 0) {
					for (i = 0; i < cur_userpass->nb_allowed_ips; i++) {
						if (strcmp(cur_userpass->allowed_ips[i], userline[2]) == 0) {
							ip_present = 1;
							break;
						}
					}
				}

				// If already present, just display a warning
				if (ip_present) {
					fprintf(stderr, "Warning: IP <%s> is already defined for user <%s>, ignored.\n", userline[2], userline[0]);
				} else { // If not, then add it then increment nb_allowed_ip
					if (cur_userpass->nb_allowed_ips == 0) {
						cur_userpass->allowed_ips = (char **) malloc(sizeof(char *));
					} else {
						cur_userpass->allowed_ips = (char **) realloc(cur_userpass->allowed_ips, sizeof(char *) * (cur_userpass->nb_allowed_ips + 1));
					}
					cur_userpass->allowed_ips[cur_userpass->nb_allowed_ips] = (char *)calloc(1, sizeof(char)* (strlen(userline[2]) + 1) );
					strcpy(cur_userpass->allowed_ips[cur_userpass->nb_allowed_ips], userline[2]);
					cur_userpass->nb_allowed_ips++;
				}
			}
		}

		// Free memory
		FREE_USERLINE

		cur_key_value = cur_key_value->next;
	}

	// Check if there is at least one user
	if (*upp == NULL)
	{
		fprintf(stderr, "Dude, you gonna need some users (key: %s) to make this thing work, edit the freakin' configuration file and add some :)\n", key);
		return EXIT_FAILURE;
	}

	// Check that each user has at least a password and an IP
	cur_userpass = *upp;
	while (cur_userpass != NULL) {
		if (cur_userpass->pass == NULL || cur_userpass->nb_allowed_ips == 0) {
			fprintf(stderr, "Fix the configuration file, the user <%s> is missing ", cur_userpass->user);
			if (cur_userpass->pass == NULL) {
				fprintf(stderr, "a password.\n");
			} else {
				fprintf(stderr, "at least one allowed IP address.\n");
			}
		}
		cur_userpass = cur_userpass->next;
	}


#ifdef DEBUG
	cur_userpass = *upp;
	printf("User list (key: %s):\n", key);
	while (cur_userpass != NULL) {
		printf("Username: %s\n", cur_userpass->user);
		printf("Password: %s\n", cur_userpass->pass);
		printf("Allowed IP (%d):", cur_userpass->nb_allowed_ips);
		for (i = 0; i < cur_userpass->nb_allowed_ips; i++) {
			printf(" %s", cur_userpass->allowed_ips[i]);
		}
		printf("\n");
		cur_userpass = cur_userpass->next;
	}
	printf("\n-----------------------\n");
#endif

	return EXIT_SUCCESS;
#undef NB_ELEM_USER_LINE
#undef FREE_USERLINE
}

void free_global_memory_config()
{
	struct key_value * cur_key_value;
	struct key_value * next;
	int i;

	// Free config
	if (_config != NULL) {
		cur_key_value = _config;
		do {
			FREE_AND_NULLIFY(cur_key_value->key);
			FREE_AND_NULLIFY(cur_key_value->value);
			next = cur_key_value->next;
			free(cur_key_value);
			cur_key_value = next;
		} while (cur_key_value != NULL);
		_config = NULL;
	}

	// Free our mac addresses list
	if (_our_macs != NULL) {
		for (i = 0; i < _nb_macs; i++) {
			free(*(_our_macs+i));
		}
		FREE_AND_NULLIFY(_our_macs);
	}

	// Free user list and sensor user list
	free_global_memory_config_userpass(&_userlist);
	free_global_memory_config_userpass(&_sensorlist);
}

void free_global_memory_config_userpass(struct userpass ** upp)
{
	struct userpass * cur, *prev;

	if (*upp != NULL) {
		prev = NULL;
		cur = *upp;

		while (cur != NULL) {
			prev = cur;
			cur = cur->next;
			free_userpass(&prev);
		}
		*upp = NULL;
	}
}