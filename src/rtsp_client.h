/*
 * RAOP : Client to control an AirPlay device, RTSP part
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Philippe <philippe_44@outlook.com>
 *
 * See LICENSE
 *
 */
 
 #ifndef __RTSP_CLIENT_H
#define __RTSP_CLIENT_H
#include <plist/plist.h>	// Required for AirPlay2 message handlers

typedef struct sock_info_s {
	int fd;
	uint16_t lport;
	uint16_t rport;
} sock_info_t;

typedef struct rtp_port_s {
	sock_info_t time;
	sock_info_t	ctrl;
	sock_info_t audio;
} rtp_port_t;

struct rtspcl_s *rtspcl_create(char* user_name);
bool   			rtspcl_destroy(struct rtspcl_s *p);

bool rtspcl_connect(struct rtspcl_s *p, struct in_addr local, struct in_addr host, unsigned short destport, char *sid);
bool rtspcl_disconnect(struct rtspcl_s *p);
bool rtspcl_is_connected(struct rtspcl_s *p);
bool rtspcl_is_sane(struct rtspcl_s *p);
bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd);
bool rtspcl_pair_verify(struct rtspcl_s *p, char *secret);
bool rtspcl_auth_setup(struct rtspcl_s *p);
bool rtspcl_announce_sdp(struct rtspcl_s *p, char *sdp, char *passwd);
bool rtspcl_setup(struct rtspcl_s *p, struct rtp_port_s *port, key_data_t *kd);
bool rtspcl_record(struct rtspcl_s *p, uint16_t start_seq, uint32_t start_ts, key_data_t *kd);
bool rtspcl_set_parameter(struct rtspcl_s *p, char *param);
bool rtspcl_flush(struct rtspcl_s *p, uint16_t seq_number, uint32_t timestamp);
bool rtspcl_set_daap(struct rtspcl_s *p, uint32_t timestamp, int count, va_list args);
bool rtspcl_set_artwork(struct rtspcl_s *p, uint32_t timestamp, char *content_type, int size, char *image);

bool rtspcl_remove_all_exthds(struct rtspcl_s *p);
bool rtspcl_add_exthds(struct rtspcl_s *p, char *key, char *data);
bool rtspcl_mark_del_exthds(struct rtspcl_s *p, char *key);
char* rtspcl_local_ip(struct rtspcl_s *p);

// AirPlay2 versions

// Get information from the AirPlay device using GET /all.
// The plist obtained with the information is returned in rplist
// The caller is responsible for calling plist_free when finished with 
// the plist data
// @param p pointer to the RTSP client handle
// @param rplist - if not NULL, the plist will be stored here
// @param rplen - the length of the returned plist will be stored here. Must be non-NUll if rplist is not NULL.
// @returns - true on success, false otherwise
bool rtspcl_get_info(struct rtspcl_s *p, plist_t *rplist, int *rplen);		
bool rtspcl_setup_session(struct rtspcl_s *p, key_data_t *kd);

#endif
