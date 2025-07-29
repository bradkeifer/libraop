/*
 * Client to control an AirPlay device
 * Items shared between AirPlay and RAOP clients
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Philippe <philippe_44@outlook.com>
 *
 * See LICENSE
 *
 */
#ifndef __COMMON_H
#define __COMMON_H

#define DEFAULT_FRAMES_PER_CHUNK 352
#define MAX_FRAMES_PER_CHUNK 4096 // must match alac_wrapper.h ALAC_MAX_FRAMES
#define SECRET_SIZE	64

typedef struct ntp_s {
	uint32_t seconds;
	uint32_t fraction;
} ntp_t;

#define NTP_EPOCH_DELTA  0x83aa7e80  /* 2208988800 - that's 1970 - 1900 in seconds */
#define NTP2MS(ntp) ((((ntp) >> 10) * 1000L) >> 22)
#define MS2NTP(ms) (((((uint64_t) (ms)) << 22) / 1000) << 10)
#define NTP2TS(ntp, rate) ((((ntp) >> 16) * (rate)) >> 16)
#define TS2NTP(ts, rate)  (((((uint64_t) (ts)) << 16) / (rate)) << 16)
#define MS2TS(ms, rate) ((((uint64_t) (ms)) * (rate)) / 1000)
#define TS2MS(ts, rate) NTP2MS(TS2NTP(ts,rate))


typedef struct {
	uint8_t proto;
	uint8_t type;
	uint8_t seq[2];
} __attribute__ ((packed)) rtp_header_t;

typedef struct {
	rtp_header_t hdr;
	uint32_t 	rtp_timestamp_latency;
	ntp_t   curr_time;
	uint32_t   rtp_timestamp;
} __attribute__ ((packed)) rtp_sync_pkt_t;

typedef struct {
	rtp_header_t hdr;
	uint32_t timestamp;
	uint32_t ssrc;
} __attribute__ ((packed)) rtp_audio_pkt_t;

struct mdnssd_handle_s;

bool AppleTVpairing(struct mdnssd_handle_s* mDNShandle, char** pUDN, char** pSecret);
bool AirPlayPassword(struct mdnssd_handle_s* mDNShandle, bool (*excluded)(char* model, char* name), char** UDN, char** passwd);

#endif