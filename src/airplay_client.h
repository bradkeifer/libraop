/*
 * AirPlay : Client to control an AirPlay2 device i.e. Not using AIRPLAY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * This code has been derived from https://github.com/owntone/owntone-server
 */

#ifndef __AIRPLAY_CLIENT_H
#define __AIRPLAY_CLIENT_H

#include <plist/plist.h>
#include "platform.h"
#include "common.h"

#define AIRPLAY_LATENCY_MIN 11025
#define GITHUB "https://github.com/bradkeifer/libraop"

typedef struct airplaycl_t {uint32_t dummy;} airplaycl_t;

struct airplaycl_s;

typedef enum airplay_codec_s { AIRPLAY_PCM = 0, AIRPLAY_ALAC_RAW, AIRPLAY_ALAC, AIRPLAY_AAC,
							AIRPLAY_AAL_ELC } airplay_codec_t;
typedef enum airplay_crypto_s { AIRPLAY_CLEAR = 0, AIRPLAY_RSA, AIRPLAY_FAIRPLAY, AIRPLAY_MFISAP,
							 AIRPLAY_FAIRPLAYSAP } airplay_crypto_t;
typedef enum airplay_states_s { AIRPLAY_DOWN = 0, AIRPLAY_FLUSHING, AIRPLAY_FLUSHED,
							 AIRPLAY_STREAMING } airplay_state_t;

typedef struct {
	int channels;
	int	sample_size;
	int	sample_rate;
	airplay_codec_t codec;
	airplay_crypto_t crypto;
} airplay_settings_t;

// if volume < -30 and not -144 or volume > 0, then not "initial set volume" will be done
struct airplaycl_s *airplaycl_create(struct in_addr host, uint16_t port_base, uint16_t port_range,
							   char *DACP_id, char *active_remote, char *user_agent,
							   airplay_codec_t codec, int frame_len, int latency_frames,
							   airplay_crypto_t crypto, bool auth, char *secret, char *passwd,
							   char *et, char *md,
							   int sample_rate, int sample_size, int channels, float volume);
bool	airplaycl_destroy(struct airplaycl_s *p);
bool	airplaycl_connect(struct airplaycl_s *p, struct in_addr host, uint16_t destport, bool set_volume);
bool 	airplaycl_repair(struct airplaycl_s *p, bool set_volume);
bool 	airplaycl_disconnect(struct airplaycl_s *p);
bool    airplaycl_flush(struct airplaycl_s *p);
bool 	airplaycl_keepalive(struct airplaycl_s *p);

bool 	 airplaycl_set_progress(struct airplaycl_s *p, uint64_t elapsed, uint64_t end);
bool 	 airplaycl_set_progress_ms(struct airplaycl_s *p, uint32_t elapsed, uint32_t duration);
uint64_t airplaycl_get_progress_ms(struct airplaycl_s* p);
bool 	 airplaycl_set_volume(struct airplaycl_s *p, float vol);
float 	 airplaycl_float_volume(int vol);
bool 	 airplaycl_set_daap(struct airplaycl_s *p, int count, ...);
bool 	 airplaycl_set_artwork(struct airplaycl_s *p, char *content_type, int size, char *image);

bool 	airplaycl_accept_frames(struct airplaycl_s *p);
bool	airplaycl_send_chunk(struct airplaycl_s *p, uint8_t *sample, int size, uint64_t *playtime);

bool 	airplaycl_start_at(struct airplaycl_s *p, uint64_t start_time);
void 	airplaycl_pause(struct airplaycl_s *p);
void 	airplaycl_stop(struct airplaycl_s *p);

/*
	These are thread safe
*/
uint32_t 	airplaycl_latency(struct airplaycl_s *p);
uint32_t 	airplaycl_sample_rate(struct airplaycl_s *p);
airplay_state_t airplaycl_state(struct airplaycl_s *p);
uint32_t 	airplaycl_queue_len(struct airplaycl_s *p);

uint32_t 	airplaycl_queued_frames(struct airplaycl_s *p);

bool 	airplaycl_is_sane(struct airplaycl_s *p);
bool 	airplaycl_is_connected(struct airplaycl_s *p);
bool 	airplaycl_is_playing(struct airplaycl_s *p);
bool 	airplaycl_sanitize(struct airplaycl_s *p);
bool 	airplaycl_assess_features(struct airplaycl_s *p);

uint64_t 	airplaycl_time32_to_ntp(uint32_t time);
uint64_t airplaycl_get_ntp(struct ntp_s* ntp);

#endif