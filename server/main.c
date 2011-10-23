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
#include <unistd.h> //sleep
#include <getopt.h>
#include "main.h"
#include "config.h"
#include "plugins.h"
#include "common/deamonize.h"
#include "messages.h"

// TODO: Handle signal to clean stuff up (especially the socket)

void help()
{
	char * temp;
	char usage[] =
	"\n"
	"  %s - (C) 2011 Thomas d\'Otreppe\n"
	"  http://www.openwips-ng.org\n"
	"\n"
	"  Usage: openwips-ng-server <config file_path>\n"
	"         or\n"
	"         openwips-ng-server [options]\n"
	"\n"
	"  Options:\n"
	"\n"
	"      -p <plugin> : Check if a plugin is valid and exit\n"
	"      -c <config> : Check if a configuration file is\n"
	"                    valid and exit\n"
	"      -i <pass>   : Hash password and exit\n"
	"      -v          : Display version and exit\n"
	"      -h          : Display help and exit\n"
	"\n";

	temp = get_prog_name();
	printf(usage, temp);
	free(temp);
	exit(-1);
}

void free_global_memory()
{
	free_global_memory_config();
	free_global_memory_sensor();
	free_global_memory_rpcap_server();
	free_global_memory_packet_assembly();
	free_global_memory_packet_analysis();
	free_global_memory_message();

	// Free the rest of memory allocated by main.
}

void init()
{
	//init_sensors_users_list();
	_stop_threads = 0;
	_config_file_location = CONFIG_FILE_LOCATION;
	_deamonize = 0;
	init_packet_assembly();
	init_sensor();
	init_packet_analysis();
	init_message_thread();
}

void stop_threads()
{
	_stop_threads = 1;
}

char * get_prog_name()
{
	char * name = (char *)malloc(28*sizeof(char));
	sprintf(name, "OpenWIPS-ng server v%d.%d.%d.%d", OPENWIPS_NG_VERSION / 1000, (OPENWIPS_NG_VERSION / 100) % 10, (OPENWIPS_NG_VERSION /10) % 10, OPENWIPS_NG_VERSION %10);
	return name;
}

int parse_args(int nbarg, char * argv[])
{
	int option_index, option;
	char * temp;
	static struct option long_options[] = {
		{"help",			0, 0, 'h'},
		{"check-plugin",	1, 0, 'p'},
		{"check-config",	1, 0, 'c'},
		{"hash-password",	1, 0, 'i'},
		{"version",			0, 0, 'v'},
		{"deamonize",		0, 0, 'd'},
		{0,             	0, 0,  0 }
	};

	while( 1 )
	{
		option_index = 0;

		option = getopt_long( nbarg, argv,
						"hp:vc:i:d",
						long_options, &option_index );

		if( option < 0 ) break;

		switch( option )
		{
			case 0 :

				break;

			case ':' :

				printf("\"%s --help\" for help.\n", argv[0]);
				return( 1 );

			case 'd' :
				//_deamonize = 1;
				fprintf(stderr, "Deamonize is not implemented yet.\n");
				break;

			case '?' :
			case 'h' :

				help();
				break;

			case 'p' : // Check plugin
#define DISPLAY_VERSION	temp = get_prog_name();printf("%s\n", temp);free(temp)
				DISPLAY_VERSION;
				load_plugin("Check Plugin", optarg, NULL, 1);
				exit(EXIT_SUCCESS);
				break;

			case 'v' :
				// Display version and exit
				DISPLAY_VERSION;
				exit(EXIT_SUCCESS);

			case 'c' : // Check configuration
				DISPLAY_VERSION;
				fprintf(stderr, "Checking configuration file <%s>\n", optarg);

				if (read_conf_file(optarg) == EXIT_SUCCESS) {
					fprintf(stderr, "[*] Configuration file <%s> is valid.\n", optarg);
				} else {
					fprintf(stderr, "[*] Configuration file <%s> is not correct.\n", optarg);
				}
				free_global_memory_config();
				exit(EXIT_SUCCESS);
				break;

			case 'i' :
				temp = get_printable_hash(optarg);
				fprintf(stderr, "%s\n", temp);
				exit(EXIT_SUCCESS);
				break;

#undef DISPLAY_VERSION
			default:
				help();
				break;
		}
	}

	return EXIT_SUCCESS;
}

int main(int nbarg, char * argv[])
{
	char * temp;

	// Parse arguments
	parse_args(nbarg, argv);

	// Initialize stuff
	init();

	if (nbarg > 2) {
		help();
	}

	if (nbarg == 2) {
		_config_file_location = argv[1];
	}

	if (_deamonize) {
		daemonize();
	}

	// Read configuration file
	fprintf(stderr, "[*] Reading configuration file <%s>.\n", _config_file_location);
	if (read_conf_file(_config_file_location) == EXIT_FAILURE) {
		fprintf(stderr, "[*] Failed to read configuration, exiting.\n");
		free_global_memory();
		return EXIT_FAILURE;
	}
	fprintf(stderr, "[*] Successfully read configuration.\n");

	if (start_message_thread() == EXIT_FAILURE) {
		fprintf(stderr, "Failed to start message thread, exiting.\n");
		free_global_memory();
		return EXIT_FAILURE;
	}

	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "OpenWIPS-ng server starting", 1);

	if (parse_plugins_config() == EXIT_FAILURE) {
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Failed to load plugins, exiting", 1);
		sleep(1); // Make sure the message is processed
		free_global_memory();
		return EXIT_FAILURE;
	}

	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Successfully loaded plugins", 1);

	if (start_packet_assembly_thread() == EXIT_FAILURE) {
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Failed to start packet reassembly and analysis thread, exiting", 1);
		sleep(1); // Make sure the message is processed
		free_global_memory();
		return EXIT_FAILURE;
	}

	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Successfully started packet reassembly thread", 1);

	if (start_packet_analysis_thread() == EXIT_FAILURE) {
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Failed to start packet analysis and analysis thread, exiting", 1);
		sleep(1); // Make sure the message is processed
		free_global_memory();
		return EXIT_FAILURE;
	}

	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Successfully started frame analysis thread", 1);

	// Start sensor socket
	if (start_sensor_socket() == EXIT_FAILURE) {
		temp = (char *)calloc(1, 100);
		sprintf(temp, "Failed to start server on port %d, exiting", _port);
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, temp, 1); // No need to free temp, the thread is going to do
		sleep(1); // Make sure the message is processed
		free_global_memory();
		return EXIT_FAILURE;
	}

	temp = (char *)calloc(1, 100);
	sprintf(temp, "Listening for sensors on port %d", _port);
	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, temp, 1); // No need to free temp, the thread is going to do it.

	// Serve
	while(1) {
		sleep(1000);
	}

	// Stop threads
	stop_threads();

	// Free memory
	free_global_memory();

	return EXIT_SUCCESS;
}
