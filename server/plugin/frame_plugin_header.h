/*
 *     License: BSD/GPLv2
 *      Author: Thomas d'Otreppe de Bouvette
 */

#ifndef FRAME_PLUGIN_HEADER_H_
#define FRAME_PLUGIN_HEADER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "../common/pcap.h"

#define MAC_LEN 6
#define COPY_MAC(source, dest, counter)	if (source) { \
											(dest)[(counter) + 1] = (unsigned char *)malloc(sizeof(unsigned char *) * MAC_LEN); \
											memcpy((dest)[(counter)++], (source), sizeof(unsigned char) * MAC_LEN); \
										}

#define FRAME_TYPE_MANAGEMENT	0
#define FRAME_TYPE_CONTROL		1
#define FRAME_TYPE_DATA			2

void * init_plugin(char * config_line, int version);
void free_memory_and_unload(void * data);
char plugin_type(void);
int min_supported_version();
int max_supported_version();
char * init_text(void * config);

int static_frame_type();
int static_frame_subtype();
int need_all_frames();
int is_single_frame_attack();
int require_packet_parsed();

int can_use_frame(struct pcap_packet * packet, void * config);
int analyze(struct pcap_packet * packet, void * config);
int nb_frames_before_analyzing(void * config);
int time_ms_before_analyzing(void * config);
int is_attacked(struct pcap_packet * packet_list, void * config);
char * attack_details(void * config);

// nb_mac indicates the amount of mac in the returned array
// deauth indicates if the macs needs to be deauthenticated.
unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth);
void clear_attack(void * config); // Cleanup any data stored about the attack by the plugin

#ifdef __cplusplus
}
#endif

#endif /* FRAME_PLUGIN_HEADER_H_ */
