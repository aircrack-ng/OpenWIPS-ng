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

#ifndef STRUCTURES_H_
#define STRUCTURES_H_

struct rpcap_link {
	int encrypted, compressed;
	int data_type; // Type of data to send
	int pasv; // Passive?
	int port;
	char * host;
};

// Data type from the rpcap_link structure
// Send every single frame
#define DATA_TYPE_EVERYTHING 0
// Frames without payload (only the headers of the wireless frames)
#define DATA_TYPE_NOPAYLOAD 1
// Everything except data frames
#define DATA_TYPE_NODATA 2
// Frames without payload and no data frames
#define DATA_TYPE_NODATA_NOPAYLOAD 3

struct rpcap_link * init_new_rpcap_link();
int free_rpcap_link(struct rpcap_link ** link);

#endif /* STRUCTURES_H_ */
