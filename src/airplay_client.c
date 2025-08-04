/*
 * AirPlay : Client to control an AirPlay2 device i.e. Not using RAOP
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
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "platform.h"

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <plist/plist.h>	// Required for AirPlay2 message handling
#include <uuid/uuid.h>
#include <gcrypt.h>

#include "alac_wrapper.h"
#include "cross_net.h"
#include "cross_log.h"
#include "cross_util.h"

#include "rtsp_client.h"
#include "airplay_client.h"
#include "aes.h"
#include "pair.h"

// AirPlay2 - plist keys
#define AIRPLAY_PLIST_FIRMWARE_VERSION				"firmwareRevision"
#define AIRPLAY_PLIST_MANUFACTURER					"manufacturer"
#define AIRPLAY_PLIST_KEEPALIVE_LOW_POWER			"keepAliiveLowPower"
#define AIRPLAY_PLIST_FIRMWARE_BUILD_DATE			"firmwareBuildDate"
#define AIRPLAY_PLIST_MODEL							"model"
#define AIRPLAY_PLIST_NAME_IS_FACTORY_DEFAULT		"nameIsFactoryDefault"
#define AIRPLAY_PLIST_HARDWARE_VERSION				"hardwareRevision"
#define AIRPLAY_PLIST_KEEPALIVE_SEND_STATS_AS_BODY	"keepAliveSendStatsAsBody"
#define AIRPLAY_PLIST_STATUS_FLAGS					"statusFlags"
#define AIRPLAY_PLIST_DEVICE_ID						"deviceID"
#define AIRPLAY_PLIST_BUILD							"build"
#define AIRPLAY_PLIST_PROTOCOL_VERSION				"protocolVersion"
#define AIRPLAY_PLIST_SOURCE_VERSION				"sourceVersion"
#define AIRPLAY_PLIST_FEATURES						"features"
#define AIRPLAY_PLIST_NAME							"name"

#define AIRPLAY_PLIST_SESSION_UUID 					"sessionUUID"
#define AIRPLAY_PLIST_TIMING_PORT 					"timingPort"
#define AIRPLAY_PLIST_TIMING_PROTOCOL 				"timingProtocol"

// Miscellaneous max sizes
#define AIRPLAY_DEVICE_ID_SIZE	17		// Max length of "deviceID" key in plist info.
#define AIRPLAY_NAME_SIZE 		64		// Max length of "name" key in plist info.

// from owntones

// For transient pairing the key_len will be 64 bytes, but only 32 are used for
// audio payload encryption. For normal pairing the key is 32 bytes.
#define AIRPLAY_AUDIO_KEY_LEN 32

// Session is starting up
#define AIRPLAY_STATE_F_STARTUP    (1 << 13)
// Streaming is up (connection established)
#define AIRPLAY_STATE_F_CONNECTED  (1 << 14)
// Couldn't start device
#define AIRPLAY_STATE_F_FAILED     (1 << 15)

enum airplay_state {
  // Device is stopped (no session)
  AIRPLAY_STATE_STOPPED   = 0,
  // Session startup
  AIRPLAY_STATE_INFO      = AIRPLAY_STATE_F_STARTUP | 0x01,
  AIRPLAY_STATE_ENCRYPTED = AIRPLAY_STATE_F_STARTUP | 0x02,
  AIRPLAY_STATE_SETUP     = AIRPLAY_STATE_F_STARTUP | 0x03,
  AIRPLAY_STATE_RECORD    = AIRPLAY_STATE_F_STARTUP | 0x04,
  // Session established
  // - streaming ready (RECORD sent and acked, connection established)
  // - commands (SET_PARAMETER) are possible
  AIRPLAY_STATE_CONNECTED = AIRPLAY_STATE_F_CONNECTED | 0x01,
  // Media data is being sent
  AIRPLAY_STATE_STREAMING = AIRPLAY_STATE_F_CONNECTED | 0x02,
  // Session teardown in progress (-> going to STOPPED state)
  AIRPLAY_STATE_TEARDOWN  = AIRPLAY_STATE_F_CONNECTED | 0x03,
  // Session is failed, couldn't startup or error occurred
  AIRPLAY_STATE_FAILED    = AIRPLAY_STATE_F_FAILED | 0x01,
  // Pending PIN or password
  AIRPLAY_STATE_AUTH      = AIRPLAY_STATE_F_FAILED | 0x02,
};

enum airplay_seq_type
{
  AIRPLAY_SEQ_ABORT = -1,
  AIRPLAY_SEQ_START,
  AIRPLAY_SEQ_START_PLAYBACK,
  AIRPLAY_SEQ_PROBE,
  AIRPLAY_SEQ_FLUSH,
  AIRPLAY_SEQ_STOP,
  AIRPLAY_SEQ_FAILURE,
  AIRPLAY_SEQ_PIN_START,
  AIRPLAY_SEQ_SEND_VOLUME,
  AIRPLAY_SEQ_SEND_TEXT,
  AIRPLAY_SEQ_SEND_PROGRESS,
  AIRPLAY_SEQ_SEND_ARTWORK,
  AIRPLAY_SEQ_PAIR_SETUP,
  AIRPLAY_SEQ_PAIR_VERIFY,
  AIRPLAY_SEQ_PAIR_TRANSIENT,
  AIRPLAY_SEQ_FEEDBACK,
  AIRPLAY_SEQ_CONTINUE, // Must be last element
};

// From https://openairplay.github.io/airplay-spec/status_flags.html
enum airplay_status_flags
{
  AIRPLAY_FLAG_PROBLEM_DETECTED               = (1 << 0),
  AIRPLAY_FLAG_NOT_CONFIGURED                 = (1 << 1),
  AIRPLAY_FLAG_AUDIO_CABLE_ATTACHED           = (1 << 2),
  AIRPLAY_FLAG_PIN_REQUIRED                   = (1 << 3),
  AIRPLAY_FLAG_SUPPORTS_FROM_CLOUD            = (1 << 6),
  AIRPLAY_FLAG_PASSWORD_REQUIRED              = (1 << 7),
  AIRPLAY_FLAG_ONE_TIME_PAIRING_REQUIRED      = (1 << 9),
  AIRPLAY_FLAG_SETUP_HK_ACCESS_CTRL           = (1 << 10),
  AIRPLAY_FLAG_SUPPORTS_RELAY                 = (1 << 11),
  AIRPLAY_FLAG_SILENT_PRIMARY                 = (1 << 12),
  AIRPLAY_FLAG_TIGHT_SYNC_IS_GRP_LEADER       = (1 << 13),
  AIRPLAY_FLAG_TIGHT_SYNC_BUDDY_NOT_REACHABLE = (1 << 14),
  AIRPLAY_FLAG_IS_APPLE_MUSIC_SUBSCRIBER      = (1 << 15),
  AIRPLAY_FLAG_CLOUD_LIBRARY_ON               = (1 << 16),
  AIRPLAY_FLAG_RECEIVER_IS_BUSY               = (1 << 17),
};

// from libraop
#define MAX_BACKLOG 512

#define JACK_STATUS_DISCONNECTED 0
#define JACK_STATUS_CONNECTED 1

#define JACK_TYPE_ANALOG 0
#define JACK_TYPE_DIGITAL 1

#define VOLUME_MIN -30
#define VOLUME_MAX 0

#define MD_TEXT		0x01
#define MD_ARTWORK	0x02
#define MD_PROGRESS	0x04

#define PUBKEY_SIZE	64

#define AIRPLAY_SEC(ntp) ((uint32_t) ((ntp) >> 32))
#define AIRPLAY_FRAC(ntp) ((uint32_t) (ntp))
#define AIRPLAY_SECNTP(ntp) AIRPLAY_SEC(ntp),AIRPLAY_FRAC(ntp)
#define AIRPLAY_MSEC(ntp)  ((uint32_t) ((((ntp) >> 16)*1000) >> 16))

/* -------------------- MISC GLOBALS derived from owntone ------------------------------ */

// @todo Copied from owntones codebase - not sure if this is required for us
#if AIRPLAY_USE_AUTH_SETUP
static const uint8_t airplay_auth_setup_pubkey[] =
  "\x59\x02\xed\xe9\x0d\x4e\xf2\xbd\x4c\xb6\x8a\x63\x30\x03\x82\x07"
  "\xa9\x4d\xbd\x50\xd8\xaa\x46\x5b\x5d\x8c\x01\x2a\x0c\x7e\x1d\x4e";
#endif

// @todo Find a more elegant way to define the minimum feature sets that we can 
//		support. Perhaps we need #define's for each bit definition and perhaps also
//		a second map structure that contains bitmaps of combinations we can support??
//		It would be good to discuss this with the community and get some suggestions
struct features_type_map
{
  uint64_t bit;			// bug in owntone code here. owntone defined as uint32_t
  char *name;
  bool mandatory;		// The device must have this feature for us to stream to it
};

// List of features announced by AirPlay 2 speakers
// Credit @invano, see https://emanuelecozzi.net/docs/airplay2
static const struct features_type_map features_map[] =
  {
    { 0, "SupportsAirPlayVideoV1" , false},
    { 1, "SupportsAirPlayPhoto" , false},
    { 5, "SupportsAirPlaySlideshow" , false},
    { 7, "SupportsAirPlayScreen" , false},
    { 9, "SupportsAirPlayAudio" , true},
    { 11, "AudioRedunant" , false},
    { 14, "Authentication_4: FairPlay" , false}, // FairPlay authentication
    { 15, "MetadataFeatures_0: Artwork" , false}, // Send artwork image to receiver
    { 16, "MetadataFeatures_1: Track progress" , false}, // Send track progress status to receiver
    { 17, "MetadataFeatures_2: NowPlaying via DAAP" , false}, // Send NowPlaying info via DAAP
    { 18, "AudioFormats_0: PCM" , false}, // PCM
    { 19, "AudioFormats_1: ALAC" , false}, // Apple Lossless (ALAC)
    { 20, "AudioFormats_2: AAC" , false}, // AAC
    { 21, "AudioFormats_3: AAC ELD" , false}, // AAC ELD (Enhanced Low Delay)
    { 23, "Authentication_1: RSA" , false}, // RSA authentication (NA)
    { 26, "Authentication_8: MFi" , false}, // 26 || 51, MFi authentication
    { 27, "SupportsLegacyPairing" , false},
    { 30, "HasUnifiedAdvertiserInfo: ?RAOP?" , false}, // or is this RAOP is supported on this port? With this bit set you don't need the AirTunes service.
    { 32, "IsCarPlay" , false},
    { 32, "SupportsVolume" , false}, // !32
    { 33, "SupportsAirPlayVideoPlayQueue" , false},
    { 34, "SupportsAirPlayFromCloud" , false}, // 34 && flags_6_SupportsAirPlayFromCloud
    { 35, "SupportsTLS_PSK" , false},
    { 38, "SupportsUnifiedMediaControl" , false},
    { 40, "SupportsBufferedAudio" , false}, // srcvers >= 354.54.6 && 40
    { 41, "SupportsPTP" , false}, // srcvers >= 366 && 41
    { 42, "SupportsScreenMultiCodec" , false},
    { 43, "SupportsSystemPairing" , false},
    { 44, "IsAPValeriaScreenSender" , false},
    { 46, "SupportsHKPairingAndAccessControl" , false},
    { 48, "SupportsCoreUtilsPairingAndEncryption" , false}, // 38 || 46 || 43 || 48
    { 49, "SupportsAirPlayVideoV2" , false},
    { 50, "MetadataFeatures_3: NowPlayng via bplist" , false}, // Send NowPlaying info via bplist
    { 51, "SupportsUnifiedPairSetupAndMFi" , false},
    { 52, "SupportsSetPeersExtendedMessage" , false},
    { 54, "SupportsAPSync" , false},
    { 55, "SupportsWoL" , false}, // 55 || 56
    { 56, "SupportsWoL" , false}, // 55 || 56
    { 58, "SupportsHangdogRemoteControl" , false}, // ((isAppleTV || isAppleAudioAccessory) && 58) || (isThirdPartyTV && flags_10)
    { 59, "SupportsAudioStreamConnectionSetup" , false}, // 59 && !disableStreamConnectionSetup
    { 60, "SupportsAudioMediaDataControl" , false}, // 59 && 60 && !disableMediaDataControl
    { 61, "SupportsRFC2198Redundancy" , false},
  };
#define AIRPLAY_FEATURE_SUPPORTS_AUDIO							((uint64_t)1 << 9)
#define AIRPLAY_FEATURE_SUPPORTS_HKPAIRINGANDACCESSCONTROL		((uint64_t)1 << 48)
#define AIRPLAY_FEATURE_SUPPORTS_COREUTILSPAIRINGANDENCRYPTION	((uint64_t)1 << 48)
#define AIRPLAY_FEATURE_SUPPORTS_UNIFIEDPAIRSETUPANDMFI 		((uint64_t)1 << 51)


/* libraop stuff
 --- timestamps (ts), millisecond (ms) and network time protocol (ntp) ---
 NTP is starting Jan 1900 (EPOCH) made of 32 high bits (seconds) and 32
 low bits (fraction).
 The player needs timestamp that increment by one for every sample (44100/s), so
 we created a "absolute" timestamp that is direcly based on NTP: it has the same
 "origin" for time.
	- TS = NTP * sample_rate / 2^32 (TS fits in 64bits no matter what)
	- NTP = TS * 2^32 / sample_rate
 Because sample_rate is less than 16 bits, then TS always have the highest 16
 bits available, so this gives, with proper rounding and avoiding overflow:
	- TS  = ((NTP >> 16) * sample_rate) >> 16
	- NTP = ((TS << 16) / sample_rate) << 16
 If we want to use a more convenient millisecond base, it must be derived from
 the same NTP and if we want to use only a 32 bits value, airplaycl_time32_to_ntp()
 do the "guess" of a 32 bits ms counter into a proper NTP

 --- head_ts ---
 The head_ts value indicates the absolute frame number of the frame to be played
 in latency seconds.
 When starting to play without a special start time, we assume that we want to
 start at the closed opportunity, so by setting the head_ts to the current
 absolute_ts (called now_ts), we are sure that the player will start to play the
 first frame at now_ts + latency, which means it has time to process a frame
 send with now_ts timestamp. We could further optimize that by reducing a bit
 this value
 When sending the 1st frame after a flush, the head_ts is reset to now_ts

 --- latency ---
 AirPlay devices seem to send everything with a latency of 11025 + the latency
 set in the sync packet, no matter what.

 --- start time ---
 As explained in the header of this file, the caller of airplaycl_set_start() must
 anticipate by airplaycl_latency() if he wants the next frame to be played exactly
 at a given NTP time

 --- airplaycl_accept_frame ---
 This function must be called before sending any data and forces the right pace
 on the caller. When running, it simply checks that now_ts is above head_ts plus
 chunk_len. But it has a critical role at start and resume. When called after a
 airplaycl_stop or airplaycl_pause has been called, it will return false until a call
 to airplaycl_flush has been finished *or* the start_time has been reached. When
 player has been actually flushed, then it will reset the head_ts to the current
 time or the start_time, force sending of the various airplay sync bits and then
 return true, resume normal mode.

 --- why airplaycl_stop/pause and airplaycl_flush ---
 It seems that they could have been merged into a single function. This allows
 independant threads for audio sending (airplaycl_accept_frames/airplaycl_send_chunks)
 and player control. The control thread can then call airplaycl_stop and queue the
 airplaycl_flush in another thread (remember that airplaycl_flush is RTSP so it can
 take time). The thread doing the audio can call airplayct_accept_frames as much
 as it wants, it will not be allowed to send anything before the *actual* flush
 is done. The control thread could even ask playback to restart immediately, no
 audio data will be accepted until flush is actually done and synchronization
 will be maintained, even in case of restart at a given time
*/


// all the following must be 32-bits aligned 

typedef struct {
	rtp_header_t hdr;
	uint32_t dummy;
	ntp_t ref_time;
	ntp_t recv_time;
	ntp_t send_time;
} __attribute__ ((packed)) rtp_time_pkt_t;

typedef struct {
	rtp_header_t hdr;
	uint16_t seq_number;
	uint16_t n;
} __attribute__ ((packed)) rtp_lost_pkt_t;


// AirPlay session handle
typedef struct airplaycl_s {
	struct rtspcl_s *rtspcl;
	airplay_state_t raop_state; // TODO <@bradkeifer> - seek to eliminate or homogenise with airplay_state
	char DACP_id[17], active_remote[11];
	struct {
		unsigned int ctrl, time;
		struct { unsigned int avail, select, send; } audio;
	} sane;
	unsigned int retransmit;
	uint8_t iv[16]; // initialization vector for aes-cbc
	uint8_t key[16]; // key for aes-cbc
	struct in_addr	peer_addr, host_addr;
	uint16_t rtsp_port;
	rtp_port_t	rtp_ports;
	struct {
		uint16_t seq_number;
		uint64_t timestamp;
		int	size;
		uint8_t *buffer;
	} backlog[MAX_BACKLOG];
	// int ajstatus, ajtype;
	float volume;
	aes_context ctx;
	int size_in_aex;
	bool encrypt;
	bool first_pkt;
	uint64_t head_ts, pause_ts, start_ts, first_ts;
	uint64_t started_ts;
	bool flushing;
	uint16_t   seq_number;
	unsigned long ssrc;
	uint32_t latency_frames;
	int chunk_len;
	pthread_t time_thread, ctrl_thread;
	pthread_mutex_t mutex;
	bool time_running, ctrl_running;
	int sample_rate, sample_size, channels;
	airplay_codec_t codec;
	struct alac_codec_s *alac_codec;
	airplay_crypto_t crypto;
	bool auth;
	char secret[SECRET_SIZE + 1];
	char et[16];
	uint8_t md_caps;
	uint16_t port_base, port_range;
	char passwd[64];

	char session_uuid[37];	// Added for AirPlay2
	uint64_t status_flags;	// Added for AirPlay2
	char device_id[AIRPLAY_DEVICE_ID_SIZE + 1]; // Added for AirPlay2
	char name[AIRPLAY_NAME_SIZE + 1]; // Added for AirPlay2
	uint64_t features; // Added for AirPlay2
	enum airplay_state state; // Added for AirPlay2 - see if can homogenise with/replace raop_state
	rtsp_response_t rtsp_response;	// Added for AirPlay2
	rtsp_request_t rtsp_request;	// Added for AirPlay2

	enum pair_type pair_type;	// Added for AirPlay 2
	struct pair_cipher_context *control_cipher_ctx; // control cipher context - airplay2
	struct pair_verify_context *pair_verify_ctx; // pair-verify context - airplay 2
	struct pair_setup_context *pair_setup_ctx; // pair-setup context - airplay 2
	enum airplay_seq_type next_seq;	// AirPlay 2

	uint8_t shared_secret[64];
	size_t	shared_secret_len;	// Length of shared secret

	gcry_cipher_hd_t packet_cipher_hd; // packet cipher context - airplay 2

} airplaycl_data_t;

extern log_level	airplay_loglevel;
extern log_level 	main_log;
static log_level 	*loglevel = &main_log;

/*----------------------- Generic Helpers ---------------------------------*/

static int 	safe_hextou64(const char *str, uint64_t *val);
static void uuid_make(char *str);
// static void device_id_colon_make(char *id_str, int size, uint64_t id);
static int 	device_id_colon_parse(uint64_t *id, const char *id_str);
static void hexdump(const char *msg, uint8_t *mem, size_t len);

/* ----------------------- AirPlay Helpers --------------------------------*/

static void airplay_session_status_log_info(struct airplaycl_s *p);
static void airplay_session_status_log_debug(struct airplaycl_s *p);

static const char* airplay_seq_type_str(enum airplay_seq_type seq);
static const char* airplay_state_str(enum airplay_state state);
static const char* airplay_pair_type_str(enum pair_type pair_type);

/* ----------------------- RTSP Helpers --------------------------------*/

static void airplay_rtsp_request_log_debug(struct airplaycl_s *p);
static bool airplay_rtsp_request_clean(struct airplaycl_s *p);
static bool airplay_rtsp_command_clean(struct airplaycl_s *p);
static bool airplay_rtsp_command_add(struct airplaycl_s *p, char *command);
static bool airplay_rtsp_content_type_clean(struct airplaycl_s *p);
static bool airplay_rtsp_content_type_add(struct airplaycl_s *p, char *content_type);
// static int airplay_rtsp_headers_get_count(struct airplaycl_s *p);
static bool airplay_rtsp_headers_clean(struct airplaycl_s *p);
static bool airplay_rtsp_headers_add(struct airplaycl_s *p, const char *key, const char *data);
static bool airplay_rtsp_body_clean(struct airplaycl_s *p);
static bool airplay_rtsp_body_add(struct airplaycl_s *p, const void *data, size_t data_len);
static int rtsp_cipher(void *vp, uint8_t *buf_out, size_t *buf_out_len, uint8_t *buf_in, int buf_in_len, int encrypt);

/*------------------------ Other Sequencing Helpers ------------------------*/

static int payload_make_setup_session(struct airplaycl_s *p);


/* ----------------------- Pairing Helpers --------------------------------*/

static bool airplay_session_sequence_start(struct airplaycl_s *p);

static int payload_make_pin_start(struct airplaycl_s *p);
static int payload_make_pair_generic(struct airplaycl_s *p, int step);
static int payload_make_pair_setup1(struct airplaycl_s *p, void* arg);
static int payload_make_pair_setup2(struct airplaycl_s *p, void* arg);
// static int payload_make_pair_setup3(struct airplaycl_s *p, void* arg);

static enum airplay_seq_type response_handler_info_generic(struct airplaycl_s *p);
static enum airplay_seq_type response_handler_info_start(struct airplaycl_s *p);


static enum airplay_seq_type response_handler_pin_start(struct airplaycl_s *p);
static enum airplay_seq_type response_handler_pair_generic(int step, struct airplaycl_s *p);
static enum airplay_seq_type response_handler_pair_setup1(struct airplaycl_s *p);
static enum airplay_seq_type response_handler_pair_setup2(struct airplaycl_s *p);
// static enum airplay_seq_type response_handler_pair_setup3(struct airplaycl_s *p);

/*---------------------- Session Ciphering / Encryption Helpers ---------------------*/

static int session_cipher_setup(struct airplaycl_s *p, const uint8_t *key, size_t key_len);
static void chacha_close(gcry_cipher_hd_t hd);
static gcry_cipher_hd_t chacha_open(const uint8_t *key, size_t key_len);
// static int chacha_encrypt(uint8_t *cipher, uint8_t *plain, size_t plain_len, const void *ad, size_t ad_len, uint8_t *tag, size_t tag_len, uint8_t *nonce, size_t nonce_len, gcry_cipher_hd_t hd);


/*----------------------- AirPlay Client Data Management ------------------*/

static bool airplaycl_analyse_info(struct airplaycl_s *p, plist_t pinfo);


/*----------------------- ? ---------------------------------*/

static void *_rtp_timing_thread(void *args);
static void *_rtp_control_thread(void *args);
static void _airplaycl_terminate_rtp(struct airplaycl_s *p);
static void _airplaycl_send_sync(struct airplaycl_s *p, bool first);
static bool _airplaycl_send_audio(struct airplaycl_s *p, rtp_audio_pkt_t *packet, int size);
static bool _airplaycl_disconnect(struct airplaycl_s *p, bool force);

/*----------------------- Generic Helpers ---------------------------------*/

// Converts hex string to a uint64
// @param str the hex string to be converted
// @param val pointer to where the converted value will be returned
// @returns 0 on success, -1 on failure
static int safe_hextou64(const char *str, uint64_t *val)
{
	char *end;
	unsigned long long intval;

	if (str == NULL) {
		LOG_DEBUG("Input to safe_hextou64 is NULL\n");
		return -1;
	}

	errno = 0;
	intval = strtoull(str, &end, 16);

	if (((errno == ERANGE) && (intval == ULLONG_MAX)) || ((errno != 0) && (intval == 0))) {
		LOG_DEBUG("Invalid u64 in string (%s): %s\n", str, strerror(errno));
		return -1;
	}

	if (end == str) {
		LOG_DEBUG("No u64 found in string (%s)\n", str);
		return -1;
	}

	if (intval > UINT64_MAX) {
		LOG_DEBUG("u64 value out of range (%s)\n", str);
		return -1;
	}

	*val = (uint64_t)intval;

	return 0;
}

// Create a uuid
// @param str a pointer to the UUID that will be created
static void uuid_make(char *str)
{
	uuid_t uu;

	uuid_generate_random(uu);
	uuid_unparse_upper(uu, str);
	LOG_DEBUG("Session UUID set to %s", str);
}

// Converts uint64t libhash -> AA:BB:CC:DD:EE:FF:11:22
// static void device_id_colon_make(char *id_str, int size, uint64_t id)
// {
// 	int r, w;

// 	snprintf(id_str, size, "%016" PRIX64, id);

// 	for (r = strlen(id_str) - 1, w = size - 2; r != w; r--, w--) {
// 		id_str[w] = id_str[r];
// 		if (r % 2 == 0) {
// 			w--;
// 			id_str[w] = ':';
// 		}
// 	}

// 	id_str[size - 1] = 0; // Zero terminate
// }

// Converts AA:BB:CC:DD:EE:FF -> AABBCCDDEEFF -> uint64 id
// @param id pointer to the "decolonised" device_id
// @paramv id_str the device id to be "decolonised"
static int device_id_colon_parse(uint64_t *id, const char *id_str)
{
	char *s;
	char *ptr;
	int ret;

	s = calloc(1, strlen(id_str) + 1);

	for (ptr = s; *id_str != '\0'; id_str++) {
		if (*id_str == ':') continue;

		*ptr = *id_str;
		ptr++;
	}

	ret = safe_hextou64(s, id);
	free(s);

	return ret;
}

// Prints a hexdump of binary data to stdout
// @param msg a heading message, if required
// mem pointer to the binary data to hexdump
// len length of data to hexdump
static void hexdump(const char *msg, uint8_t *mem, size_t len)
{
  int i, j;
  int hexdump_cols = 16;

  if (msg)
    printf("%s", msg);

  for (i = 0; i < len + ((len % hexdump_cols) ? (hexdump_cols - len % hexdump_cols) : 0); i++)
    {
      if(i % hexdump_cols == 0)
	printf("0x%06x: ", i);

      if (i < len)
	printf("%02x ", 0xFF & ((char*)mem)[i]);
      else
	printf("   ");

      if (i % hexdump_cols == (hexdump_cols - 1))
	{
	  for (j = i - (hexdump_cols - 1); j <= i; j++)
	    {
	      if (j >= len)
		putchar(' ');
	      else if (isprint(((char*)mem)[j]))
		putchar(0xFF & ((char*)mem)[j]);
	      else
		putchar('.');
	    }

	  putchar('\n');
	}
    }
}
/* ----------------------- AirPlay Helpers --------------------------------*/

// Print LOG_INFO output of current state of airplay session
// @param p the AirPlay 2 client handle
static void airplay_session_status_log_info(struct airplaycl_s *p) {
	LOG_DEBUG("Pair type: %s (%d), State: %s (%d), Sequence %s (%d), Status Flags 0x%0x",
		airplay_pair_type_str(p->pair_type), p->pair_type, 
		airplay_state_str(p->state), p->state, 
		airplay_seq_type_str(p->next_seq), p->next_seq, 
		p->status_flags);
}

// Print LOG_DEBUG output of current state of airplay session
// @param p the AirPlay 2 client handle
static void airplay_session_status_log_debug(struct airplaycl_s *p) {
	LOG_DEBUG("Pair type: %s (%d), State: %s (%d), Sequence %s (%d), Status Flags 0x%0x",
		airplay_pair_type_str(p->pair_type), p->pair_type, 
		airplay_state_str(p->state), p->state, 
		airplay_seq_type_str(p->next_seq), p->next_seq, 
		p->status_flags);
}

// Helper to display human readable sequence type
// @param seq_type the sequence type to get human readable text
// @returns human readable description of the sequence type
static const char* airplay_seq_type_str(enum airplay_seq_type seq_type) {
	switch(seq_type) {
		case AIRPLAY_SEQ_ABORT:
			return("Abort");
		case AIRPLAY_SEQ_START:
			return("Start");
		case AIRPLAY_SEQ_START_PLAYBACK:
			return("Start Playback");
		case AIRPLAY_SEQ_PROBE:
			return("Probe");
		case AIRPLAY_SEQ_FLUSH:
			return("Flush");
		case AIRPLAY_SEQ_STOP:
			return("Stop");
		case AIRPLAY_SEQ_FAILURE:
			return("Failure");
		case AIRPLAY_SEQ_PIN_START:
			return("PIN Start");
		case AIRPLAY_SEQ_SEND_VOLUME:
			return("Send Volume");
		case AIRPLAY_SEQ_SEND_TEXT:
			return("Send Text");
		case AIRPLAY_SEQ_SEND_PROGRESS:
			return("Send Progress");
		case AIRPLAY_SEQ_SEND_ARTWORK:
			return("Send Artwork");
		case AIRPLAY_SEQ_PAIR_SETUP:
			return("Pair Setup");
		case AIRPLAY_SEQ_PAIR_VERIFY:
			return("Pair Verify");
		case AIRPLAY_SEQ_PAIR_TRANSIENT:
			return("Pair Transient");
		case AIRPLAY_SEQ_FEEDBACK:
			return("Feedback");
		case AIRPLAY_SEQ_CONTINUE:
			return("Continue");
		default:
			return("Illegal seq_type value");
	}
}

// Helper to display human readable description of the airplay state
// @param state the state to get human readable text
// @returns human readable description of the airplay state
static const char* airplay_state_str(enum airplay_state state) {
	switch(state) {
		case AIRPLAY_STATE_STOPPED:
			return("Device Stopped");
		case AIRPLAY_STATE_INFO:
			return("Session Startup Info");
		case AIRPLAY_STATE_ENCRYPTED:
			return("Session Startup Encrypted");
		case AIRPLAY_STATE_SETUP:
			return("Session Startup Setup");
		case AIRPLAY_STATE_RECORD:
			return("Session Startup Record");
		case AIRPLAY_STATE_CONNECTED:
			return("Session established");
		case AIRPLAY_STATE_STREAMING:
			return("Connected Streaming");
		case AIRPLAY_STATE_TEARDOWN:
			return("Teardown in progress");
		case AIRPLAY_STATE_FAILED:
			return("Session Failed");
		case AIRPLAY_STATE_AUTH:
			return("Pending PIN or Password");
		default:
			return("Illegal state value");
	}
}

// Helper to display human readable description of the pairing type
// @param state the state to get human readable text
// @returns human readable description of the airplay state
static const char* airplay_pair_type_str(enum pair_type pair_type) {
	switch(pair_type) {
		case PAIR_CLIENT_FRUIT:
			return("Pair Client Fruit (Apple TV)");
		case PAIR_CLIENT_HOMEKIT_NORMAL:
			return("Homekit Normal");
		case PAIR_CLIENT_HOMEKIT_TRANSIENT:
			return("Homekit Transient");
		case PAIR_SERVER_HOMEKIT:
			return("Session Startup Setup");
		default:
			return("Illegal pair_type value");
	}
}

// LOG_DEBUG the current state of the RTSP Request
// @param p the AirPlay 2 Client Handle
static void airplay_rtsp_request_log_debug(struct airplaycl_s *p){
	if (!p) {
		LOG_ERROR("Invalid AirPlay client handle");
		return;
	}

	LOG_DEBUG("RTSP Request current status is:");
	LOG_DEBUG("Command: %s", p->rtsp_request.command);
	LOG_DEBUG("Content Type: %s", p->rtsp_request.content_type);
	for (size_t i = 0; i < p->rtsp_request.headers.count; i++) {
		LOG_DEBUG("%s: %s", p->rtsp_request.headers.kd[i].key,
			p->rtsp_request.headers.kd[i].data);
	}
	LOG_DEBUG("RTSP Body length: %d", p->rtsp_request.body.length);
}

static bool airplay_rtsp_request_clean(struct airplaycl_s *p) {
	if (!p) {
		LOG_ERROR("Invalid AirPlay client handle");
		return false;
	}

	LOG_DEBUG("Command clean");
	if (!airplay_rtsp_command_clean(p)) return false;
	LOG_DEBUG("Content Type clean");
	if (!airplay_rtsp_content_type_clean(p)) return false;
	LOG_DEBUG("Headers clean");
	if (!airplay_rtsp_headers_clean(p)) return false;
	LOG_DEBUG("Body clean");
	if (!airplay_rtsp_body_clean(p)) return false;

	return true;
}

static bool airplay_rtsp_command_clean(struct airplaycl_s *p) {
	if (!p) {
		LOG_ERROR("Invalid AirPlay client handle");
		return false;
	}

	p->rtsp_request.command[0] = '\0';

	return true;
}

static bool airplay_rtsp_command_add(struct airplaycl_s *p, char *command) {
	if (!p) {
		LOG_ERROR("Invalid AirPlay client handle");
		return false;
	}

	if (strlen(command) > sizeof(p->rtsp_request.command)) {
		LOG_ERROR("Command too long. %d > %d", strlen(command), sizeof(p->rtsp_request.command));
		return false;
	}

	strncpy(p->rtsp_request.command, command, sizeof(p->rtsp_request.command));

	return true;
}

static bool airplay_rtsp_content_type_clean(struct airplaycl_s *p) {
	if (!p) {
		LOG_ERROR("Invalid AirPlay client handle");
		return false;
	}

	p->rtsp_request.content_type[0] = '\0';

	return true;
}

static bool airplay_rtsp_content_type_add(struct airplaycl_s *p, char *content_type) {
	if (!p) {
		LOG_ERROR("Invalid AirPlay client handle");
		return false;
	}

	if (strlen(content_type) > sizeof(p->rtsp_request.content_type)) {
		LOG_ERROR("Content Type too long. %d > %d", strlen(content_type), sizeof(p->rtsp_request.content_type));
		return false;
	}

	strncpy(p->rtsp_request.content_type, content_type, sizeof(p->rtsp_request.content_type));

	return true;
}

// Get the number of RTSP Headers currently stored
// @param p the AirPlay client handle
// @returns the number of RTSP Headers or -1 on error.
// static int airplay_rtsp_headers_get_count(struct airplaycl_s *p) {
// 	if (!p) {
// 		LOG_ERROR("Invalid AirPlay client handle");
// 		return -1;
// 	}

// 	return p->rtsp_request.headers.count;
// }

// Clean/reset the RTSP request Headers buffer
// @param p the AirPlay client handle
// @returns true on success, false on failure
static bool airplay_rtsp_headers_clean(struct airplaycl_s *p) {

	if (!p) {
		LOG_ERROR("Invalid Airplay client handle");
		return false;
	}

	if (p->rtsp_request.headers.count == 0) {
		LOG_WARN("RTSP Headers already clean");
		return true;
	}

	kd_free(p->rtsp_request.headers.kd);
	p->rtsp_request.headers.count = 0;

	return true;
}

// Add key data item to the RTSP request headers buffer
// @param p the AirPlay client handle
// @param key pointer to the key value 
// @param data pointer to the data value
// @returns true on success, false on failure
static bool airplay_rtsp_headers_add(struct airplaycl_s *p, const char *key, const char *data) {
	size_t i = 0;

	if (!p) {
		LOG_ERROR("Invalid AirPlay client handle");
		return false;
	}

	if (!key || strlen(key) == 0 || strlen(key) > RTSP_MAX_KD_LENGTH) {
		LOG_ERROR("Invalid key");
		return false;
	}

	if (!data || strlen(data) == 0 || strlen(data) > RTSP_MAX_KD_LENGTH) {
		LOG_ERROR("Invalid data");
		return false;
	}

	if (p->rtsp_request.headers.count >= MAX_KD) {
		LOG_ERROR("Maximum Key Data count of %d will be exceeded", MAX_KD);
		return false;
	}

	i = p->rtsp_request.headers.count;
	p->rtsp_request.headers.kd[i].key = strdup(key);
	if (p->rtsp_request.headers.kd[i].key == (char *)NULL) {
		LOG_ERROR("Unable to allocate memory for key %s", key);
		return false;
	}

	p->rtsp_request.headers.kd[i].data = strdup(data);
	if (p->rtsp_request.headers.kd[i].data == (char *)NULL) {
		LOG_ERROR("Unable to allocate memory for data %s", data);
		return false;
	}
	p->rtsp_request.headers.count++;

	LOG_DEBUG("Added %s: %s to key data. Count now is %d",
		p->rtsp_request.headers.kd[p->rtsp_request.headers.count - 1].key,
		p->rtsp_request.headers.kd[p->rtsp_request.headers.count - 1].data,
		p->rtsp_request.headers.count);

	return true;
}

// Clean/reset the RTSP request payload buffer
// @param p the AirPlay client handle
// @returns true on success, false on failure
static bool airplay_rtsp_body_clean(struct airplaycl_s *p) {
	if (!p) {
		LOG_ERROR("Invalid Airplay client handle");
		return false;
	}
	p->rtsp_request.body.length = 0;
	memset(p->rtsp_request.body.mem, 0, RTSP_MAX_BODY);
	return true;
}

// Append data to the RTSP request body buffer
// @param p the AirPlay client handle
// @param data pointer to the data to be added
// @param data_len the length of data to be added
// @returns true on success, false on failure
static bool airplay_rtsp_body_add(struct airplaycl_s *p, const void *data, size_t data_len) {
	if (!p || !data || data_len == 0) {
		LOG_ERROR("Invalid paramaters");
		return false;
	}
	if ((p->rtsp_request.body.length + data_len) > RTSP_MAX_BODY) {
		LOG_ERROR("New data add would cause body overflow. %d + %d > %d",
			p->rtsp_request.body.length, data_len, RTSP_MAX_BODY);
		return false;
	}
	memcpy(&p->rtsp_request.body.mem[p->rtsp_request.body.length], data, data_len);
	p->rtsp_request.body.length += data_len;
	return true;
}

// Callback function for encrypting or decrypting RTSP data
// @param p the AirPlay 2 Session Client handle
// @param outbuf the ciphering buffer where the results of encryption/decryption will be returned
// @param inbuf the data to be encrypted/decrypted
// @param encrypt encryption if value os non-zero, decryption if value is zero.
// @note this needs to move back into airplay.c to remain aligned with owntones derived design
static int rtsp_cipher(void *vp, uint8_t *buf_out, size_t *buf_out_len, uint8_t *buf_in, int buf_in_len, int encrypt)
{
	uint8_t *in;
	size_t in_len;
	uint8_t *out = NULL;
	size_t out_len = 0;
	ssize_t processed;
	struct airplaycl_s *p = (struct airplaycl_s *)vp;


	// in = evbuffer_pullup(inbuf, -1);
	// in_len = evbuffer_get_length(inbuf);
	in = buf_in;
	in_len = buf_in_len;

	if (encrypt) {
#if AIRPLAY_DUMP_TRAFFIC
		if (in_len < 4096) {
			hexdump("Encrypting outgoing request\n", in, in_len);
		}
		else {
			LOG_DEBUG("Encrypting outgoing request (size %zu)\n", in_len);
		}
#endif

		processed = pair_encrypt(&buf_out, buf_out_len, buf_in, buf_in_len, p->control_cipher_ctx);
		if (processed < 0) {
			goto error;
		}
	}
	else {
		processed = pair_decrypt(&buf_out, buf_out_len, buf_in, buf_in_len, p->control_cipher_ctx);
		if (processed < 0) {
			goto error;
		}

#if AIRPLAY_DUMP_TRAFFIC
		if (out_len < 4096) {
			hexdump("Decrypted incoming response\n", out, out_len);
		}
		else {
			LOG_DEBUG("Decrypted incoming response (size %zu)\n", out_len);
		}
#endif
	}

	// evbuffer_drain(inbuf, processed);
	// evbuffer_add(outbuf, out, out_len);

	return 0;

error:
	LOG_ERROR("Error while %s (len=%zu): %s\n", encrypt ? "encrypting" : "decrypting", 
		buf_in_len, pair_cipher_errmsg(p->control_cipher_ctx));

	return -1;
}

/*--------------------- Other Sequencing Helpers - logic sourced from owntones ---------------------------*/


static int payload_make_setup_session(struct airplaycl_s *p)
{
	plist_t root;
	// plist_t addresses;
	// plist_t address;
	plist_t add;
	char *out = NULL;
	uint32_t out_len = 0;
	uint8_t *data;
	size_t len;

	// address = plist_new_string(p->host_addr.s_addr);
	// addresses = plist_new_array();
	// plist_array_append_item(addresses, address);

	root = plist_new_dict();

	add = plist_new_string(p->device_id);
	plist_dict_set_item(root, AIRPLAY_PLIST_DEVICE_ID, add);

	add = plist_new_string(p->session_uuid);
	plist_dict_set_item(root, AIRPLAY_PLIST_SESSION_UUID, add);

	add = plist_new_uint(p->rtp_ports.time.lport);
	plist_dict_set_item(root, AIRPLAY_PLIST_TIMING_PORT, add);

	add = plist_new_string("NTP");
	plist_dict_set_item(root, AIRPLAY_PLIST_TIMING_PROTOCOL, add); // If set to "None" then an ATV4 will not respond to stream SETUP request

	plist_to_bin(root, &out, &out_len);
	if (!out) {
		LOG_ERROR("Unable to convert plist to binary");
		plist_free(root);
		return -1;
	}
	data = (uint8_t *)out;
	len = out_len;

	plist_free(root);

	airplay_rtsp_command_add(p, "SETUP");
	airplay_rtsp_content_type_add(p, AIRPLAY_CONTENT_TYPE_PLIST);
	airplay_rtsp_body_add(p, data, len);

	return 0;
}


/*--------------------- Pairing Helpers - some logic sourced from owntones  ------------------------------*/

// Start the RTSP dialogue with the AirPlay device
// @param p pointer to the airplay client handle
// @returns true on success, false on failure
// @note this emulates sequence_start(AIRPLAY_SEQ_START, rs, NULL, "device_start") from owntones
static bool airplay_session_sequence_start(struct airplaycl_s *p) {
	// To start the dialogue, we send RTSP GET /info to obtain airplay device details 
	// that will be required in future exchanges and we analyse the statusFlags to
	// determine the pairing approach required
	if (!rtspcl_get_info(p->rtspcl, &p->rtsp_response)) {
		LOG_ERROR("[%p]: cannot get info", p);
		return false;
	}

	// Using the below commented out code as a replacement for rtspcl_get_info() results
	// in a segmentation fault in airplaycl_analyse_info() - not sure why and need to focus on
	// getting other aspects of this implementation to work at the moment. Come back to this another day.
	// if (!airplay_rtsp_content_type_add(p, NULL)) {
	// 	LOG_ERROR("Unable to set Content Type to %s", NULL);
	// 	return false;
	// }
	// if (!airplay_rtsp_command_add(p, "GET /info")) {
	// 	LOG_ERROR("Unable to set RTSP Request command to %s", "GET /info");
	// 	return false;
	// }
	// rtspcl_process_request(p->rtspcl, &p->rtsp_request, &p->rtsp_response);
	// airplay_rtsp_request_clean(p);

	if (!strncmp(p->rtsp_response.content_type, AIRPLAY_CONTENT_TYPE_PLIST, 
		strlen(AIRPLAY_CONTENT_TYPE_PLIST))) {
		LOG_ERROR("%s returned Content-Type %s, but require %s", p->name, 
			p->rtsp_response.content_type,  AIRPLAY_CONTENT_TYPE_PLIST);
		return false;
	}
	if (!p->rtsp_response.content) {
		LOG_ERROR("No RTSP content returned from rtspcl_get_info()");
		return false;
	}
	LOG_DEBUG("About the analyse info (%p), content-type %s", p->rtsp_response.content, p->rtsp_response.content_type);
	if (!airplaycl_analyse_info(p, (plist_t)p->rtsp_response.content)) {
		LOG_ERROR("Unable to analyse GET /info plist\n");
		return false;
	}
	LOG_WARN("Check to see if we do indeed free p->rtsp_response.content later in program execution");
	return true;
}

static int payload_make_pin_start(struct airplaycl_s *p)
{
	LOG_INFO("Starting device pairing for '%s', go to the web interface and enter PIN\n", p->name);

	airplay_rtsp_command_add(p, PAIR_AP_POST_PIN_START);
	if (p->pair_type == PAIR_CLIENT_HOMEKIT_NORMAL)
		airplay_rtsp_headers_add(p, "X-Apple-HKP", "3");
	else if (p->pair_type == PAIR_CLIENT_HOMEKIT_TRANSIENT)
		airplay_rtsp_headers_add(p, "X-Apple-HKP", "4");

	return 0;
}

// Generic handler for constructing RTSP pairing data
// @param p the AirPlay client handle
// @param step	the step number in the pairing sequence
// @returns 0 on success, -1 on failure
// @note The RTSP Request Headers and PAyload information in the AirPlay client handle
// @note are updated by the function. The caller is responsible for ensuring clean RTSP
// @note request data before initiation.
static int payload_make_pair_generic(struct airplaycl_s *p, int step)
{
	uint8_t *body;
	size_t len;
	const char *errmsg;


	switch (step) {
		case 1:
			body    = pair_setup_request1(&len, p->pair_setup_ctx);
			errmsg  = pair_setup_errmsg(p->pair_setup_ctx);
			break;
		case 2:
			body    = pair_setup_request2(&len, p->pair_setup_ctx);
			errmsg  = pair_setup_errmsg(p->pair_setup_ctx);
			break;
		case 3:
			body    = pair_setup_request3(&len, p->pair_setup_ctx);
			errmsg  = pair_setup_errmsg(p->pair_setup_ctx);
			break;
			//   case 4:
			// body    = pair_verify_request1(&len, p->pair_verify_ctx);
			// errmsg  = pair_verify_errmsg(p->pair_verify_ctx);
			// break;
			//   case 5:
			// body    = pair_verify_request2(&len, p->pair_verify_ctx);
			// errmsg  = pair_verify_errmsg(p->pair_verify_ctx);
			// break;
		default:
			body    = NULL;
			errmsg  = "Bug! Bad step number";
	}

	if (!body) {
		LOG_ERROR("Verification step %d request error: %s", step, errmsg);
		return -1;
	}

	LOG_DEBUG("Need to add %d bytes to the rtsp output buffer", len);
	hexdump("Output buffer\n", body, len);
	LOG_DEBUG("errmsg is %s", errmsg);
	airplay_rtsp_body_add(p, body, len);
	free(body);

	// Required!!
	if (p->pair_type == PAIR_CLIENT_HOMEKIT_NORMAL)
		airplay_rtsp_headers_add(p, "X-Apple-HKP", "3");
	else if (p->pair_type == PAIR_CLIENT_HOMEKIT_TRANSIENT)
		airplay_rtsp_headers_add(p, "X-Apple-HKP", "4");

	return 0;
}

// Handles pair-setup step 1
// @param p the AirPlay client handle
// @param arg the PIN to use for pairing
// @returns 0 on success, -1 on failure
// @note The RTSP Request Headers and PAyload information in the AirPlay client handle
// @note are updated by the function. The caller is responsible for ensuring clean RTSP
// @note request data before initiation.
static int payload_make_pair_setup1(struct airplaycl_s *p, void* arg)
{
	const char *pin = arg;
	uint64_t device_id = 0;
	char device_id_hex[16 + 1];

	if (!pin && p->passwd[0])
		pin = &p->passwd[0]; // For password based authentication

	if (pin)
		p->pair_type = PAIR_CLIENT_HOMEKIT_NORMAL;

	device_id_colon_parse(&device_id, p->device_id);
	snprintf(device_id_hex, sizeof(device_id_hex), "%016" PRIX64, device_id);
	LOG_DEBUG("Calling pair_setup_new with pair-type %s, pin %s, device_id %016" PRIX64,
		airplay_pair_type_str(p->pair_type), pin, device_id_hex);

	p->pair_setup_ctx = pair_setup_new(p->pair_type, pin, NULL, NULL, device_id_hex);
	if (!p->pair_setup_ctx) {
		LOG_ERROR("Out of memory for verification setup context");
		return -1;
	}
	airplay_rtsp_command_add(p, PAIR_AP_POST_SETUP);

	p->state = AIRPLAY_STATE_AUTH;

	return payload_make_pair_generic(p, 1);
}

static int
payload_make_pair_setup2(struct airplaycl_s *p, void *arg)
{
	airplay_rtsp_command_add(p, PAIR_AP_POST_SETUP);
	return payload_make_pair_generic(p, 2);
}

// static int
// payload_make_pair_setup3(struct airplaycl_s *p, void *arg)
// {
// 	airplay_rtsp_command_add(p, PAIR_AP_POST_SETUP);
// 	return payload_make_pair_generic(p, 3);
// }

// Extract statusFlags from plist in RTSP Response and determine next sequence
// @param response the RTSP response data
// @param p the AirPlay 2 client handle
static enum airplay_seq_type response_handler_info_generic(struct airplaycl_s *p)
{
	// struct output_device *device;
	plist_t response =(plist_t)p->rtsp_response.content;
	plist_t item;
	// int ret;

	// device = outputs_device_get(rs->device_id);
	// if (!device)
	// return AIRPLAY_SEQ_ABORT;

	// ret = session_ids_set(rs);
	// if (ret < 0)
	// {
	// 	DPRINTF(E_LOG, L_AIRPLAY, "Could not make session url or id for device '%s'\n", rs->devname);
	// 	return AIRPLAY_SEQ_ABORT;
	// }

	// ret = wplist_from_evbuf(&response, req->input_buffer);
	// if (ret < 0)
	// {
	// 	DPRINTF(E_LOG, L_AIRPLAY, "Could not parse plist from '%s'\n", rs->devname);
	// 	return AIRPLAY_SEQ_ABORT;
	// }

	item = plist_dict_get_item(response, "statusFlags");
	if (item) plist_get_uint_val(item, &p->status_flags);

	plist_free(response);

	LOG_DEBUG("Status flags from '%s' was %" PRIu64 ": cable attached %d, one time pairing %d, password %d, PIN %d",
	p->name, p->status_flags, (bool)(p->status_flags & AIRPLAY_FLAG_AUDIO_CABLE_ATTACHED), (bool)(p->status_flags & AIRPLAY_FLAG_ONE_TIME_PAIRING_REQUIRED),
	(bool)(p->status_flags & AIRPLAY_FLAG_PASSWORD_REQUIRED), (bool)(p->status_flags & AIRPLAY_FLAG_PIN_REQUIRED));

	// Identify next sequence based on response
	if (p->status_flags & AIRPLAY_FLAG_ONE_TIME_PAIRING_REQUIRED) {
		p->pair_type = PAIR_CLIENT_HOMEKIT_NORMAL;

		LOG_WARN("HOMEKIT_NORMAL pairing with PIN or PAIR VERIFY is not yet fully implemented");

		// if (!device->auth_key) {
		// 	device->requires_auth = 1;
		// 		p->state = AIRPLAY_STATE_AUTH;
		// 	return AIRPLAY_SEQ_PIN_START;
		// }

		p->state = AIRPLAY_STATE_INFO;
		return AIRPLAY_SEQ_PAIR_VERIFY;
	}
	else if (p->status_flags & AIRPLAY_FLAG_PIN_REQUIRED) {
		// free(device->auth_key);
		// device->auth_key = NULL;
		// device->requires_auth = 1;

		p->pair_type = PAIR_CLIENT_HOMEKIT_NORMAL;
		p->state = AIRPLAY_STATE_AUTH;
		LOG_WARN("HOMEKIT_NORMAL pairing with PIN is not yet fully implemented");
		return AIRPLAY_SEQ_PIN_START;
	}
	else if (p->status_flags & AIRPLAY_FLAG_PASSWORD_REQUIRED) {
		p->pair_type = PAIR_CLIENT_HOMEKIT_NORMAL;

		if (!p->passwd[0]) {
			LOG_DEBUG("'%s requires password authentication, but none given in config", p->name);
			return AIRPLAY_SEQ_ABORT;
		}
		// else if (!device->auth_key) {
		// 	p->state = AIRPLAY_STATE_AUTH;
		// 	return AIRPLAY_SEQ_PAIR_SETUP;
		// }

		LOG_WARN("HOMEKIT_NORMAL pairing with password is not yet fully implemented");
		p->state = AIRPLAY_STATE_INFO;
		return AIRPLAY_SEQ_PAIR_VERIFY;
	}

	p->pair_type = PAIR_CLIENT_HOMEKIT_TRANSIENT;
	p->state = AIRPLAY_STATE_INFO;
	return AIRPLAY_SEQ_PAIR_TRANSIENT;
}

static enum airplay_seq_type response_handler_info_start(struct airplaycl_s *p)
{
	enum airplay_seq_type seq_type;

	seq_type = response_handler_info_generic(p);
	if (seq_type != AIRPLAY_SEQ_ABORT && seq_type != AIRPLAY_SEQ_PIN_START) {
		p->next_seq = AIRPLAY_SEQ_START_PLAYBACK; // Pair and then run SEQ_START_PLAYBACK which sets up the playback
	}

	return seq_type;
}

// Response handler for pairing with a PIN
// @param p The AirPlay 2 Client Handle
// @returns the next sequence
static enum airplay_seq_type response_handler_pin_start(struct airplaycl_s *p)
{
  p->state = AIRPLAY_STATE_AUTH;

  return AIRPLAY_SEQ_CONTINUE; // TODO before we reported failure since device is locked
}

static enum airplay_seq_type response_handler_pair_generic(int step, struct airplaycl_s *p)
{
	uint8_t *response;
	const char *errmsg;
	size_t len;
	int ret;

	response = (uint8_t *)p->rtsp_response.content;
	len = p->rtsp_response.length;
	LOG_INFO("Response data length is %d", len);

	switch (step) {
		case 1:
			ret = pair_setup_response1(p->pair_setup_ctx, response, len);
			errmsg = pair_setup_errmsg(p->pair_setup_ctx);
			break;
		case 2:
			ret = pair_setup_response2(p->pair_setup_ctx, response, len);
			errmsg = pair_setup_errmsg(p->pair_setup_ctx);
			break;
		case 3:
			ret = pair_setup_response3(p->pair_setup_ctx, response, len);
			errmsg = pair_setup_errmsg(p->pair_setup_ctx);
			break;
		// case 4:
		// 	ret = pair_verify_response1(rs->pair_verify_ctx, response, len);
		// 	errmsg = pair_verify_errmsg(rs->pair_verify_ctx);
		// 	break;
		// case 5:
		// 	ret = pair_verify_response2(rs->pair_verify_ctx, response, len);
		// 	errmsg = pair_verify_errmsg(rs->pair_verify_ctx);
		// 	break;
		default:
			ret = -1;
			errmsg = "Bug! Bad step number";
	}

	if (ret < 0) {
		LOG_ERROR("Pairing step %d response from '%s' error: %s", step, p->name, errmsg);
		hexdump("Raw response", response, len);
		return AIRPLAY_SEQ_ABORT;
	}

	return AIRPLAY_SEQ_CONTINUE;
}

static enum airplay_seq_type response_handler_pair_setup1(struct airplaycl_s *p)
{
	if (p->pair_type == PAIR_CLIENT_HOMEKIT_TRANSIENT && 
		p->rtsp_response.status_code == RTSP_CONNECTION_AUTH_REQUIRED) {

		// I suspect this deals with the case where the device is removed by owntones.
		// Not sure if there is a MASS equivalent?
		// device = outputs_device_get(rs->device_id);
		// if (!device)
		// 	return AIRPLAY_SEQ_ABORT;

		if (!p->auth) {
			LOG_WARN("%s defined as not requiring authorisation, but it does", p->name);
			p->auth = true;
		}
		p->pair_type = PAIR_CLIENT_HOMEKIT_NORMAL;

		LOG_DEBUG("Returing next sequence=AIRPLAY_SEQ_PIN_START, "
			"with pair_type PAIR_CLIENT_HOMEKIT_NORMAL");
		return AIRPLAY_SEQ_PIN_START;
	}

	return response_handler_pair_generic(1, p);
}


static enum airplay_seq_type response_handler_pair_setup2(struct airplaycl_s *p)
{
	enum airplay_seq_type seq_type;
	struct pair_result *result;
	int ret;

	seq_type = response_handler_pair_generic(2, p);
	if (seq_type != AIRPLAY_SEQ_CONTINUE)
	return seq_type;

	if (p->pair_type != PAIR_CLIENT_HOMEKIT_TRANSIENT)
	return seq_type;

	ret = pair_setup_result(NULL, &result, p->pair_setup_ctx);
	if (ret < 0) {
		LOG_ERROR("Transient setup result error: %s\n", pair_setup_errmsg(p->pair_setup_ctx));
		goto error;
	}


	ret = session_cipher_setup(p, result->shared_secret, result->shared_secret_len);
	if (ret < 0) {
		LOG_ERROR("Pair transient error setting up encryption for '%s'\n", p->name);
		goto error;
	}

	return AIRPLAY_SEQ_CONTINUE;

error:
	p->state = AIRPLAY_STATE_FAILED;
	return AIRPLAY_SEQ_ABORT;
}

// static enum airplay_seq_type response_handler_pair_setup3(struct airplaycl_s *p)
// {
// 	// struct output_device *device;
// 	const char *authorization_key;
// 	enum airplay_seq_type seq_type;
// 	int ret;

// 	seq_type = response_handler_pair_generic(3, p);
// 	if (seq_type != AIRPLAY_SEQ_CONTINUE)
// 	return seq_type;

// 	ret = pair_setup_result(&authorization_key, NULL, p->pair_setup_ctx);
// 	if (ret < 0) {
// 		LOG_ERROR("Pair setup result error: %s\n", pair_setup_errmsg(p->pair_setup_ctx));
// 		return AIRPLAY_SEQ_ABORT;
// 	}

// 	LOG_INFO("Pair setup stage complete, saving authorization key\n");

// 	//   device = outputs_device_get(rs->device_id);
// 	//   if (!device)
// 	//     return AIRPLAY_SEQ_ABORT;

// 	LOG_WARN("Implement a method to save the authorization key for future use");
// 	// free(device->auth_key);
// 	// device->auth_key = strdup(authorization_key);

// 	// A blocking db call... :-~
// 	// db_speaker_save(device);

// 	// No longer AIRPLAY_STATE_AUTH
// 	p->state = AIRPLAY_STATE_STOPPED;

// 	return AIRPLAY_SEQ_CONTINUE;
// }

/*----------------------- Session Ciphering / Encryption Helpers --------------------------*/


// Setup cipher contexts and details, namely the shared secret, control cipher context (used for RTSP?)
// and the packet cipher context (used for streaming?)
// @param p the AirPlay 2 session client handle
// @param key the shared secret key
// @param key_len the shared secret key length 
// @returns 0 on success, -1 on failure
static int session_cipher_setup(struct airplaycl_s *p, const uint8_t *key, size_t key_len)
{
	struct pair_cipher_context *control_cipher_ctx = NULL;
	gcry_cipher_hd_t packet_cipher_hd = NULL;

	// For transient pairing the key_len will be 64 bytes, and rs->shared_secret is 32 bytes
	if (key_len < AIRPLAY_AUDIO_KEY_LEN || key_len > sizeof(p->shared_secret))
	{
		LOG_ERROR("Ciphering setup error: Unexpected key length (%zu)\n", key_len);
		goto error;
	}

	p->shared_secret_len = key_len;
	memcpy(p->shared_secret, key, key_len);

	control_cipher_ctx = pair_cipher_new(p->pair_type, 0, key, key_len);
	if (!control_cipher_ctx)
	{
		LOG_ERROR("Could not create control ciphering context\n");
		goto error;
	}

	packet_cipher_hd = chacha_open(p->shared_secret, AIRPLAY_AUDIO_KEY_LEN);
	if (!packet_cipher_hd)
	{
		LOG_ERROR("Could not create packet ciphering handle\n");
		goto error;
	}

	LOG_DEBUG("Ciphering setup of '%s' completed succesfully, now using encrypted mode\n", p->name);

	p->state = AIRPLAY_STATE_ENCRYPTED;
	p->control_cipher_ctx = control_cipher_ctx;
	p->packet_cipher_hd = packet_cipher_hd;

	rtspcl_set_ciphercb(p->rtspcl, rtsp_cipher, p);
	LOG_INFO("RTSP cipher callback has been set");

	return 0;

	error:
	pair_cipher_free(control_cipher_ctx);
	chacha_close(packet_cipher_hd);
	return -1;
}

static void chacha_close(gcry_cipher_hd_t hd)
{
	if (!hd)
	return;

	gcry_cipher_close(hd);
}

static gcry_cipher_hd_t chacha_open(const uint8_t *key, size_t key_len)
{
	gcry_cipher_hd_t hd;

	if (gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0) != GPG_ERR_NO_ERROR) {
		goto error;
	}

	if (gcry_cipher_setkey(hd, key, key_len) != GPG_ERR_NO_ERROR) {
		goto error;
	}

	return hd;

error:
	chacha_close(hd);
	return NULL;
}

// static int chacha_encrypt(uint8_t *cipher, uint8_t *plain, size_t plain_len, const void *ad, size_t ad_len, uint8_t *tag, size_t tag_len, uint8_t *nonce, size_t nonce_len, gcry_cipher_hd_t hd)
// {
// 	if (gcry_cipher_setiv(hd, nonce, nonce_len) != GPG_ERR_NO_ERROR) {
// 		return -1;
// 	}

// 	if (gcry_cipher_authenticate(hd, ad, ad_len) != GPG_ERR_NO_ERROR) {
// 		return -1;
// 	}

// 	if (gcry_cipher_encrypt(hd, cipher, plain_len, plain, plain_len) != GPG_ERR_NO_ERROR) {
// 		return -1;
// 	}

// 	if (gcry_cipher_gettag(hd, tag, tag_len) != GPG_ERR_NO_ERROR) {
// 		return -1;
// 	}

// 	return 0;
// }


/*----------------------------------------------------------------------------*/
airplay_state_t airplaycl_state(struct airplaycl_s *p)
{
	if (!p) return AIRPLAY_DOWN;
	return p->raop_state;
}


/*----------------------------------------------------------------------------*/
uint32_t airplaycl_latency(struct airplaycl_s *p)
{
	if (!p) return 0;
	// why do AirPlay devices use required latency + 11025 ???
	return p->latency_frames + AIRPLAY_LATENCY_MIN;
}


/*----------------------------------------------------------------------------*/
uint32_t airplaycl_sample_rate(struct airplaycl_s *p)
{
	if (!p) return 0;
	return p->sample_rate;
}

/* -------------------------- Current NTP timestamp --------------------------- */
uint64_t airplaycl_get_ntp(struct ntp_s* ntp)
{
	uint64_t time = gettime_us();
	uint32_t seconds = time / (1000 * 1000);
	seconds += NTP_EPOCH_DELTA; // Convert to NTP epoch (1900-01-01)
	uint32_t fraction = ((time % (1000 * 1000)) << 32) / (1000 * 1000);

	if (ntp) {
		ntp->seconds = seconds;
		ntp->fraction = fraction;
	}

	return ((uint64_t) seconds << 32) | fraction;
}


/*----------------------------------------------------------------------------*/
uint64_t airplaycl_time32_to_ntp(uint32_t time)
{
	uint64_t ntp_ms = ((airplaycl_get_ntp(NULL) >> 16) * 1000) >> 16;
	uint32_t ms = (uint32_t) ntp_ms;
	uint64_t res;

	/*
	 Received time is supposed to be derived from an NTP in a form of
	 (NTP.second * 1000 + NTP.fraction / 1000) & 0xFFFFFFFF
	 with many rollovers as NTP started in 1900. It's also assumed that "time"
	 is not older then 60 seconds
	*/
	if (ms > time + 60000 || ms + 60000 < time) ntp_ms += 0x100000000LL;

	res = ((((ntp_ms & 0xffffffff00000000LL) | time) << 16) / 1000) << 16;

	return res;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_is_connected(struct airplaycl_s *p)
{
	bool rc;

	if (!p) return false;

	pthread_mutex_lock(&p->mutex);
	rc = rtspcl_is_connected(p->rtspcl);
	pthread_mutex_unlock(&p->mutex);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_is_sane(struct airplaycl_s *p)
{
	if (p && p->raop_state == AIRPLAY_STREAMING &&
		(!rtspcl_is_sane(p->rtspcl) ||
		 (p->sane.audio.send + p->sane.audio.avail*5 +  p->sane.audio.select*50) >= 500 ||
		 p->sane.ctrl > 2 || p->sane.time > 2)) return false;

	return true;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_is_playing(struct airplaycl_s *p)
{
	uint64_t now_ts = NTP2TS(airplaycl_get_ntp(NULL), p->sample_rate);

	if (!p) return false;

	if (p->pause_ts || now_ts < p->head_ts + airplaycl_latency(p)) return true;
	else return false;
}

/*----------------------------------------------------------------------------*/
// static int rsa_encrypt(uint8_t *text, int len, uint8_t *res)
// {
// 	RSA *rsa;
// 	uint8_t modules[256];
// 	uint8_t exponent[8];
// 	int size;
// 	char n[] =
// 			"59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUtwC"
// 			"5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDR"
// 			"KSKv6kDqnw4UwPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuB"
// 			"OitnZ/bDzPHrTOZz0Dew0uowxf/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJ"
// 			"Q+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/UAaHqn9JdsBWLUEpVviYnh"
// 			"imNVvYFZeCXg/IdTQ+x4IRdiXNv5hEew==";
// 	char e[] = "AQAB";
// 	BIGNUM *n_bn, *e_bn;

// 	rsa = RSA_new();
// 	size = base64_decode(n, modules);
// 	n_bn = BN_bin2bn(modules, size, NULL);
// 	size = base64_decode(e, exponent);
// 	e_bn = BN_bin2bn(exponent, size, NULL);
// 	RSA_set0_key(rsa, n_bn, e_bn, NULL);
// 	size = RSA_public_encrypt(len, text, res, rsa, RSA_PKCS1_OAEP_PADDING);
// 	RSA_free(rsa);

// 	return size;
// }

/*----------------------------------------------------------------------------*/
static int airplaycl_encrypt(airplaycl_data_t *airplaycld, uint8_t *data, int size)
{
	uint8_t *buf;
	uint8_t nv[16];
	int i=0,j;
	memcpy(nv,airplaycld->iv,16);
	while(i+16<=size){
		buf=data+i;
		for(j=0;j<16;j++) buf[j] ^= nv[j];
		aes_encrypt(&airplaycld->ctx, buf, buf);
		memcpy(nv,buf,16);
		i+=16;
	}
#if 0
	if(i<size){
		uint8_t tmp[16];
		LOG_INFO("[%p]: a block less than 16 bytes(%d) is not encrypted", airplaycld, size-i);
		memset(tmp,0,16);
		memcpy(tmp,data+i,size-i);
		for(j=0;j<16;j++) tmp[j] ^= nv[j];
		aes_encrypt(&airplaycld->ctx, tmp, tmp);
		memcpy(nv,tmp,16);
		memcpy(data+i,tmp,16);
		i+=16;
	}
#endif
	return i;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_keepalive(struct airplaycl_s *p) {
	return rtspcl_options(p->rtspcl, NULL);
}

/*----------------------------------------------------------------------------*/
void airplaycl_pause(struct airplaycl_s *p)
{
	if (!p || p->raop_state != AIRPLAY_STREAMING) return;

	pthread_mutex_lock(&p->mutex);

	p->pause_ts = p->head_ts;
	p->flushing = true;

	pthread_mutex_unlock(&p->mutex);

	LOG_INFO("[%p]: set pause %" PRIu64 "", p, p->pause_ts);
}

/*----------------------------------------------------------------------------*/
bool airplaycl_start_at(struct airplaycl_s *p, uint64_t start_time)
{
	if (!p) return false;

	pthread_mutex_lock(&p->mutex);

	p->start_ts = NTP2TS(start_time, p->sample_rate);

	pthread_mutex_unlock(&p->mutex);

	LOG_INFO("[%p]: set start time %u.%u (ts:%" PRIu64 ")", p, AIRPLAY_SEC(start_time), AIRPLAY_FRAC(start_time), p->start_ts);

	return true;
}

/*----------------------------------------------------------------------------*/
void airplaycl_stop(struct airplaycl_s *p)
{
	if (!p) return;

	pthread_mutex_lock(&p->mutex);

	p->flushing = true;
	p->pause_ts = 0;

	pthread_mutex_unlock(&p->mutex);
}

/*----------------------------------------------------------------------------*/
bool airplaycl_accept_frames(struct airplaycl_s *p)
{
	bool accept = false, first_pkt = false;
	uint64_t now_ts;

	if (!p) return 0;

	pthread_mutex_lock(&p->mutex);

	// a flushing is pending
	if (p->flushing) {
		uint64_t now = airplaycl_get_ntp(NULL);

		now_ts = NTP2TS(now, p->sample_rate);

		// Not flushed yet, but we have time to wait, so pretend we are full
		if (p->raop_state != AIRPLAY_FLUSHED && (!p->start_ts || p->start_ts > now_ts + airplaycl_latency(p))) {
			pthread_mutex_unlock(&p->mutex);
			return false;
		 }

		// move to streaming only when really flushed - not when timedout
		if (p->raop_state == AIRPLAY_FLUSHED) {
			p->first_pkt = first_pkt = true;
			LOG_INFO("[%p]: begining to stream hts:%" PRIu64 " n:%u.%u", p, p->head_ts, AIRPLAY_SECNTP(now));
			p->raop_state = AIRPLAY_STREAMING;
		}

		// unpausing ...
		if (!p->pause_ts) {
			p->head_ts = p->first_ts = p->start_ts ? p->start_ts : now_ts;
			if (first_pkt) _airplaycl_send_sync(p, true);
			LOG_INFO("[%p]: restarting w/o pause n:%u.%u, hts:%" PRIu64 "", p, AIRPLAY_SECNTP(now), p->head_ts);
		}
		else {
			uint16_t n, i, chunks = airplaycl_latency(p) / p->chunk_len;

			// if un-pausing w/o start_time, can anticipate as we have buffer
			p->first_ts = p->start_ts ? p->start_ts : now_ts - airplaycl_latency(p);

			// last head_ts shall be first + airplaycl_latency - chunk_len
			p->head_ts = p->first_ts - p->chunk_len;

			if (first_pkt) _airplaycl_send_sync(p, true);

			LOG_INFO("[%p]: restarting w/ pause n:%u.%u, hts:%" PRIu64 " (re-send: %d)", p, AIRPLAY_SECNTP(now), p->head_ts, chunks);

			// search pause_ts in backlog, it should be backward, not too far
			for (n = p->seq_number, i = 0;
				 i < MAX_BACKLOG && p->backlog[n % MAX_BACKLOG].timestamp > p->pause_ts;
				 i++, n--) { };

			 // the resend shall go up to (including) pause_ts
			 n = (n - chunks + 1) % MAX_BACKLOG;

			// re-send old packets
			for (i = 0; i < chunks; i++) {
				rtp_audio_pkt_t *packet;
				uint16_t reindex, index = (n + i) % MAX_BACKLOG;

				if (!p->backlog[index].buffer) continue;

				p->seq_number++;

				packet = (rtp_audio_pkt_t*) (p->backlog[index].buffer + sizeof(rtp_header_t));
				packet->hdr.seq[0] = (p->seq_number >> 8) & 0xff;
				packet->hdr.seq[1] = p->seq_number & 0xff;
				packet->timestamp = htonl(p->head_ts);
				packet->hdr.type = 0x60 | (p->first_pkt ? 0x80 : 0);
				p->first_pkt = false;

				// then replace packets in backlog in case
				reindex = p->seq_number % MAX_BACKLOG;

				p->backlog[reindex].seq_number = p->seq_number;
				p->backlog[reindex].timestamp = p->head_ts;
				if (p->backlog[reindex].buffer) free(p->backlog[reindex].buffer);
				p->backlog[reindex].buffer = p->backlog[index].buffer;
				p->backlog[reindex].size = p->backlog[index].size;
				p->backlog[index].buffer = NULL;

				p->head_ts += p->chunk_len;

				_airplaycl_send_audio(p, packet, p->backlog[reindex].size);
			}

			LOG_DEBUG("[%p]: finished resend %u", p, i);
		}

		p->pause_ts = p->start_ts = 0;
		p->flushing = false;
	}

	// when paused, fix "now" at the time when it was paused.
	if (p->pause_ts) now_ts = p->pause_ts;
	else now_ts = NTP2TS(airplaycl_get_ntp(NULL), p->sample_rate);

	if (now_ts >= p->head_ts + p->chunk_len) accept = true;

	pthread_mutex_unlock(&p->mutex);

	return accept;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_send_chunk(struct airplaycl_s *p, uint8_t *sample, int frames, uint64_t *playtime)
{
	uint8_t *encoded, *buffer;
	rtp_audio_pkt_t *packet;
	size_t n;
	int size;
	uint64_t now = airplaycl_get_ntp(NULL);

	if (!p || !sample) {
		LOG_ERROR("[%p]: something went wrong (s:%p)", p, sample);
		return false;
	}

	pthread_mutex_lock(&p->mutex);

	/*
	 Move to streaming state only when really flushed. In most cases, this is
	 done by the airplaycl_accept_frames function, except when a player takes too
	 long to flush (JBL OnBeat) and we have to "fake" accepting frames
	*/
	if (p->raop_state == AIRPLAY_FLUSHED) {
		p->first_pkt = true;
		LOG_INFO("[%p]: begining to stream (LATE) hts:%" PRIu64 " n:%u.%u", p, p->head_ts, AIRPLAY_SECNTP(now));
		p->raop_state = AIRPLAY_STREAMING;
		_airplaycl_send_sync(p, true);
	}

	switch (p->codec) {
		case AIRPLAY_ALAC:
			pcm_to_alac(p->alac_codec, sample, frames, &encoded, &size);
			break;
		case AIRPLAY_ALAC_RAW:
			pcm_to_alac_raw(sample, frames, &encoded, &size, p->chunk_len);
			break;
		case AIRPLAY_PCM: {
			uint8_t *src = sample, *dst = encoded = malloc(frames * 4);
			for (size = 0; size < frames; size++) {
				*dst++ = *(src + 1); *dst++ = *src++;
				*dst++ = *(++src + 1); *dst++ = *src++;
				src++;
			}
			size *= 4;
			break;
		}
		default:
			LOG_ERROR("[%p]: don't know what we're doing here", p);
			return false;
	}

	if ((buffer = malloc(sizeof(rtp_header_t) + sizeof(rtp_audio_pkt_t) + size)) == NULL) {
		pthread_mutex_unlock(&p->mutex);
		if (encoded) free(encoded);
		LOG_ERROR("[%p]: cannot allocate buffer",p);
		return false;
	}

	*playtime = TS2NTP(p->head_ts + airplaycl_latency(p), p->sample_rate);

	LOG_SDEBUG("[%p]: sending audio ts:%" PRIu64 " (pt:%u.%u now:%" PRIu64 ") ", p, p->head_ts, AIRPLAY_SEC(*playtime), AIRPLAY_FRAC(*playtime), airplaycl_get_ntp(NULL));

	p->seq_number++;

	// packet is after re-transmit header
	packet = (rtp_audio_pkt_t *) (buffer + sizeof(rtp_header_t));
	packet->hdr.proto = 0x80;
	packet->hdr.type = 0x60 | (p->first_pkt ? 0x80 : 0);
	p->first_pkt = false;
	packet->hdr.seq[0] = (p->seq_number >> 8) & 0xff;
	packet->hdr.seq[1] = p->seq_number & 0xff;
	packet->timestamp = htonl(p->head_ts);
	packet->ssrc = htonl(p->ssrc);

	memcpy((uint8_t*) packet + sizeof(rtp_audio_pkt_t), encoded, size);

	// with newer airport express, don't use encryption (??)
	if (p->encrypt) airplaycl_encrypt(p, (uint8_t*) packet + sizeof(rtp_audio_pkt_t), size);

	n = p->seq_number % MAX_BACKLOG;
	p->backlog[n].seq_number = p->seq_number;
	p->backlog[n].timestamp = p->head_ts;
	if (p->backlog[n].buffer) free(p->backlog[n].buffer);
	p->backlog[n].buffer = buffer;
	p->backlog[n].size = sizeof(rtp_audio_pkt_t) + size;

	p->head_ts += p->chunk_len;

	_airplaycl_send_audio(p, packet, sizeof(rtp_audio_pkt_t) + size);

	pthread_mutex_unlock(&p->mutex);

	if (NTP2MS(*playtime) % 60000 < 8) {
		LOG_INFO("[%p]: check n:%u p:%u ts:%" PRIu64 " sn:%u\n               "
				  "retr: %u, avail: %u, send: %u, select: %u)", p,
				 AIRPLAY_MSEC(now), AIRPLAY_MSEC(*playtime), p->head_ts, p->seq_number,
				 p->retransmit, p->sane.audio.avail, p->sane.audio.send,
				 p->sane.audio.select);
	}

	if (encoded) free(encoded);

	return true;
}

/*----------------------------------------------------------------------------*/
bool _airplaycl_send_audio(struct airplaycl_s *p, rtp_audio_pkt_t *packet, int size)
{
	struct timeval timeout;
	fd_set wfds;
	struct sockaddr_in addr;
	size_t n;
	bool ret = true;

	/*
	 Do not send if audio port closed or we are not yet in streaming state. We
	 might be just waiting for flush to happen in the case of a device taking a
	 lot of time to connect, so avoid disturbing it with frames. Still, for sync
	 reasons or when a starting time has been set, it's normal that the caller
	 uses airplaycld_accept_frames() and tries to send frames even before the
	 connect has returned in case of multi-threaded application
	*/
	if (p->rtp_ports.audio.fd == -1 || p->raop_state != AIRPLAY_STREAMING) return false;

	addr.sin_family = AF_INET;
	addr.sin_addr = p->peer_addr;
	addr.sin_port = htons(p->rtp_ports.audio.rport);

	FD_ZERO(&wfds);
	FD_SET(p->rtp_ports.audio.fd, &wfds);

	/*
	  The audio socket is non blocking, so we can can wait socket availability
	  but not too much. Half of the packet size if a good value. There is the
	  backlog buffer to re-send packets if needed, so nothign is lost
	*/
	timeout.tv_sec = 0;
	timeout.tv_usec = (p->chunk_len * 1000000L) / (p->sample_rate * 2);

	if (select(p->rtp_ports.audio.fd + 1, NULL, &wfds, NULL, &timeout) == -1) {
		LOG_ERROR("[%p]: audio socket closed", p);
		p->sane.audio.select++;
	}
	else p->sane.audio.select = 0;

	if (FD_ISSET(p->rtp_ports.audio.fd, &wfds)) {
		n = sendto(p->rtp_ports.audio.fd, (void*) packet, + size, 0, (void*) &addr, sizeof(addr));
		if (n != size) {
			LOG_DEBUG("[%p]: error sending audio packet", p);
			ret = false;
			p->sane.audio.send++;
		}
		else p->sane.audio.send = 0;
		p->sane.audio.avail = 0;
	}
	else {
		LOG_DEBUG("[%p]: audio socket unavailable", p);
		ret = false;
		p->sane.audio.avail++;
	}

	return ret;
}

/* ---------------------------- Module management ------------------------ */
struct airplaycl_s *airplaycl_create(struct in_addr host, uint16_t port_base, uint16_t port_range,
							   char *DACP_id, char *active_remote, char *user_agent,
							   airplay_codec_t codec, int chunk_len, int latency_frames,
							   airplay_crypto_t crypto, bool auth, char *secret, char *passwd,
							   char *et, char *md,
							   int sample_rate, int sample_size, int channels, float volume)
{
	struct airplaycl_s *airplaycld;

    LOG_DEBUG("Creating AirPlay session for host %s with DACP ID %s", inet_ntoa(host), DACP_id);

	if (chunk_len > MAX_FRAMES_PER_CHUNK) {
		LOG_ERROR("Chunk length must below %d", MAX_FRAMES_PER_CHUNK);
		return NULL;
	}

	airplaycld = malloc(sizeof(airplaycl_data_t));
	memset(airplaycld, 0, sizeof(airplaycl_data_t));

	//  airplaycld->sane is set to 0
	uuid_make(airplaycld->session_uuid);
	airplaycld->port_base = port_base;
	airplaycld->port_range = port_base ? port_range : 1;
	airplaycld->sample_rate = sample_rate;
	airplaycld->sample_size = sample_size;
	airplaycld->channels = channels;
	airplaycld->volume = volume;
	airplaycld->codec = codec;
	airplaycld->crypto = crypto;
	airplaycld->auth = auth;
	if (passwd) strncpy(airplaycld->passwd, passwd, sizeof(airplaycld->passwd) - 1);
	if (secret) strncpy(airplaycld->secret, secret, SECRET_SIZE);
	if (et) strncpy(airplaycld->et, et, 16);
	airplaycld->latency_frames = max(latency_frames, AIRPLAY_LATENCY_MIN);
	airplaycld->chunk_len = chunk_len;
	strcpy(airplaycld->DACP_id, DACP_id ? DACP_id : "");
	strcpy(airplaycld->active_remote, active_remote ? active_remote : "");
	airplaycld->host_addr = host;
	airplaycld->rtp_ports.ctrl.fd = airplaycld->rtp_ports.time.fd = airplaycld->rtp_ports.audio.fd = -1;
	airplaycld->seq_number = rand();

	if (md && strchr(md, '0')) airplaycld->md_caps |= MD_TEXT;
	if (md && strchr(md, '1')) airplaycld->md_caps |= MD_ARTWORK;
	if (md && strchr(md, '2')) airplaycld->md_caps |= MD_PROGRESS;

	// LOG_DEBUG("rtsp response = %d", airplaycld->rtsp_response.rtsp_response);

	// init RTSP if needed
	if (((airplaycld->rtspcl = rtspcl_create(user_agent)) == NULL)) {
		LOG_ERROR("[%p]: Cannot create RTSP context", airplaycld);
		free(airplaycld);
		return NULL;
	}

	if (codec == AIRPLAY_ALAC && (airplaycld->alac_codec = alac_create_encoder(airplaycld->chunk_len, sample_rate, sample_size, channels)) == NULL) {
		LOG_WARN("[%p]: cannot create ALAC codec", airplaycld);
		airplaycld->codec = AIRPLAY_ALAC_RAW;
	}

	LOG_INFO("[%p]: using %s coding", airplaycld, airplaycld->alac_codec ? "ALAC" : "PCM");

	pthread_mutex_init(&airplaycld->mutex, NULL);

	RAND_bytes(airplaycld->iv, sizeof(airplaycld->iv));
	VALGRIND_MAKE_MEM_DEFINED(airplaycld->iv, sizeof(airplaycld->iv));
	RAND_bytes(airplaycld->key, sizeof(airplaycld->key));
	VALGRIND_MAKE_MEM_DEFINED(airplaycld->key, sizeof(airplaycld->key));

	aes_set_key(&airplaycld->ctx, airplaycld->key, 128);

	airplaycl_sanitize(airplaycld);

	return airplaycld;
  
}


/*----------------------------------------------------------------------------*/
static void _airplaycl_terminate_rtp(struct airplaycl_s *p)
{
	// Terminate RTP threads and close sockets
	p->ctrl_running = false;
	pthread_join(p->ctrl_thread, NULL);

	p->time_running = false;
	pthread_join(p->time_thread, NULL);

	if (p->rtp_ports.ctrl.fd != -1) closesocket(p->rtp_ports.ctrl.fd);
	if (p->rtp_ports.time.fd != -1) closesocket(p->rtp_ports.time.fd);
	if (p->rtp_ports.audio.fd != -1) closesocket(p->rtp_ports.audio.fd);

	p->rtp_ports.ctrl.fd = p->rtp_ports.time.fd = p->rtp_ports.audio.fd = -1;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_set_volume(struct airplaycl_s *p, float vol)
{
	char a[128];

	if (!p) return false;

	if ((vol < -30 || vol > 0) && vol != -144.0) return false;

	p->volume = vol;

	if (!p->rtspcl || p->raop_state < AIRPLAY_FLUSHED) return true;

	sprintf(a, "volume: %f\r\n", vol);

	return rtspcl_set_parameter(p->rtspcl, a);
}

/*----------------------------------------------------------------------------*/
// minimum=0, maximum=100
float airplaycl_float_volume(int vol)
{
	if (vol == 0) return -144.0;
	return VOLUME_MIN + ((VOLUME_MAX - VOLUME_MIN) * (float) vol) / 100;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_set_progress_ms(struct airplaycl_s *p, uint32_t elapsed, uint32_t duration)
{
	return airplaycl_set_progress(p, MS2NTP(elapsed), MS2NTP(duration));
}

/*----------------------------------------------------------------------------*/
bool airplaycl_set_progress(struct airplaycl_s *p, uint64_t elapsed, uint64_t duration)
{
	char a[128];
	uint64_t end, now;

	if (!p || !p->rtspcl || p->raop_state < AIRPLAY_STREAMING || !(p->md_caps & MD_PROGRESS)) return false;

	now = NTP2TS(airplaycl_get_ntp(NULL), p->sample_rate);
	p->started_ts = now - NTP2TS(elapsed, p->sample_rate);
	end = duration ? p->started_ts + NTP2TS(duration, p->sample_rate) : now;

	sprintf(a, "progress: %u/%u/%u\r\n", (uint32_t) p->started_ts, (uint32_t) now, (uint32_t) end);

	return rtspcl_set_parameter(p->rtspcl, a);
}

/*----------------------------------------------------------------------------*/
uint64_t airplaycl_get_progress_ms(struct airplaycl_s* p) 
{
	uint64_t elapsed, now;

	if (!p || p->raop_state < AIRPLAY_FLUSHING || !p->rtspcl || !(p->md_caps & MD_PROGRESS)) return 0;

	// if we have no pause_ts and we are flushing or are not streaming, then we are stopped
	if ((p->flushing || p->raop_state < AIRPLAY_STREAMING) && !p->pause_ts) return 0;

	// we are not stopped, then pause_ts is to be taken into account if not 0
	now = p->pause_ts ? p->pause_ts : NTP2TS(airplaycl_get_ntp(NULL), p->sample_rate);
	elapsed = TS2MS(now - p->started_ts, p->sample_rate);

	return elapsed;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_set_artwork(struct airplaycl_s *p, char *content_type, int size, char *image)
{
	if (!p || !p->rtspcl || p->raop_state < AIRPLAY_FLUSHED || !(p->md_caps & MD_ARTWORK)) return false;

	return rtspcl_set_artwork(p->rtspcl, p->head_ts + p->latency_frames, content_type, size, image);
}

/*----------------------------------------------------------------------------*/
bool airplaycl_set_daap(struct airplaycl_s *p, int count, ...)
{
	va_list args;

	if (!p || p->raop_state < AIRPLAY_FLUSHED || !(p->md_caps & MD_TEXT)) return false;

	va_start(args, count);

	return rtspcl_set_daap(p->rtspcl, p->head_ts + p->latency_frames, count, args);
}

/*----------------------------------------------------------------------------*/
// Extract AirPlay player information that is required for managing the session
// and store it in the airplay_s structure
// @param p the airplay client handle that will be updated
// @param pinfo the binary plist containing the airplay device information
// @returns true on success, false on failure
// @todo Perhaps use this function to "connect" to the owntones sequencing logic/functions??
// @note This emulates some of the owntones response_handler_info_generic. Try to harmonise
// this function into that one in the future.
static bool airplaycl_analyse_info(struct airplaycl_s *p, plist_t pinfo) {
	const char *device_id = NULL;
	const char *name = NULL;
	plist_t item = NULL;

	// Extract the device id and save into our airplay client data structure
	item = plist_dict_get_item(pinfo, AIRPLAY_PLIST_DEVICE_ID);
	if (item) {
		device_id = (char *) plist_get_string_ptr(item, NULL);
		LOG_DEBUG("Device ID: %s", device_id);
	}
	else {
		LOG_ERROR("No Device ID. Please raise an issue in %s", GITHUB);
		return false;
	}

	if (strlen(device_id) > AIRPLAY_DEVICE_ID_SIZE) {
		LOG_ERROR("Device Id %s exceeds maximum size of %d bytes", device_id, AIRPLAY_DEVICE_ID_SIZE);
		LOG_ERROR("Please raise an issue in %s", GITHUB);
		goto erexit;
	}
	else {
		strncpy(p->device_id, device_id, strlen(device_id));
	}

	// Extract the device name and save into our airplay client data structure
	item = plist_dict_get_item(pinfo, AIRPLAY_PLIST_NAME);
	if (item) {
		name = (char *) plist_get_string_ptr(item, NULL);
		LOG_DEBUG("Device ID: %s", name);
	}
	else {
		LOG_ERROR("No Device name. Please raise an issue in %s", GITHUB);
		return false;
	}

	if (strlen(name) > AIRPLAY_NAME_SIZE) {
		LOG_ERROR("Device Id %s exceeds maximum size of %d bytes", name, AIRPLAY_NAME_SIZE);
		LOG_ERROR("Please raise an issue in %s", GITHUB);
		goto erexit;
	}
	else {
		strncpy(p->name, name, strlen(name));
	}

	// Extract features
	item = plist_dict_get_item(pinfo, AIRPLAY_PLIST_FEATURES);
	if (item) {
		plist_get_uint_val(item, &p->features);
		LOG_INFO("%s has features %" PRIX64 "\n", p->name, p->features);
		plist_free(item);
	}
	if (!airplaycl_assess_features(p)) {
		LOG_ERROR("%s does not meet minimum capability for us to support", p->name);
		return false;
	}

	return true;

erexit:
	plist_free(item);
	return false;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_connect(struct airplaycl_s *p, struct in_addr peer, uint16_t destport, bool set_volume)
{
	struct {
		uint32_t sid;
		uint64_t sci;
		uint8_t sac[16];
	} seed;
	char sid[10+1], sci[16+1];
	char *sac = NULL;
	key_data_t kd[64];
	struct {
		uint16_t count, offset;
	} port = { 0 };

	if (!p) return false;

	if (p->raop_state >= AIRPLAY_FLUSHING) return true;

	kd[0].key = NULL;
	port.offset = rand() % p->port_range;

	if (peer.s_addr != INADDR_ANY) p->peer_addr.s_addr = peer.s_addr;
	if (destport != 0) p->rtsp_port = destport;

	RAND_bytes((uint8_t*) &p->ssrc, sizeof(p->ssrc));
	VALGRIND_MAKE_MEM_DEFINED(&p->ssrc, sizeof(p->ssrc));

	p->encrypt = (p->crypto != AIRPLAY_CLEAR);
	memset(&p->sane, 0, sizeof(p->sane));
	p->retransmit = 0;

	RAND_bytes((uint8_t*) &seed, sizeof(seed));
	VALGRIND_MAKE_MEM_DEFINED(&seed, sizeof(seed));
	sprintf(sid, "%010lu", (long unsigned int) seed.sid);
	sprintf(sci, "%016llx", (long long int) seed.sci);

	// RTSP misc setup
	rtspcl_add_exthds(p->rtspcl,"Client-Instance", sci); // Owntones makes this the same as DACP-ID
	if (*p->DACP_id) rtspcl_add_exthds(p->rtspcl,"DACP-ID", p->DACP_id);
	if (*p->active_remote) rtspcl_add_exthds(p->rtspcl,"Active-Remote", p->active_remote);

	// RTSP connect
	if (!rtspcl_connect(p->rtspcl, p->host_addr, peer, destport, sid)) goto erexit;

	LOG_INFO("[%p]: local interface %s", p, rtspcl_local_ip(p->rtspcl));

	// RTSP GET /info
	if (!airplay_session_sequence_start(p)) {
		LOG_ERROR("Unable to start RTSP session with %s", p->name);
		goto erexit;
	}
	p->next_seq = response_handler_info_start(p);
	airplay_rtsp_request_clean(p);
	airplay_session_status_log_debug(p);

	if (p->pair_type == PAIR_CLIENT_HOMEKIT_TRANSIENT &&
		p->state == AIRPLAY_STATE_INFO &&
		p->next_seq == AIRPLAY_SEQ_PAIR_TRANSIENT) {

		// RTSP POST /pair-setup (step 1)
		airplay_rtsp_content_type_add(p, AIRPLAY_CONTENT_TYPE_OCTET_STREAM);
		if (payload_make_pair_setup1(p, NULL) == -1) {
			LOG_ERROR("Error constructing the RTSP pairing request");
			goto erexit;
		}
		airplay_rtsp_request_log_debug(p);
		rtspcl_process_request(p->rtspcl, &p->rtsp_request, &p->rtsp_response);

		// Now handle the response and free the response memory
		p->next_seq = response_handler_pair_setup1(p);
		airplay_rtsp_request_clean(p);
		airplay_session_status_log_debug(p);
		
		if (p->pair_type == PAIR_CLIENT_HOMEKIT_TRANSIENT &&
			p->state == AIRPLAY_STATE_AUTH &&
			p->next_seq == AIRPLAY_SEQ_CONTINUE) {

			// RTSP POST /pair-setup (step 2)
			airplay_rtsp_content_type_add(p, AIRPLAY_CONTENT_TYPE_OCTET_STREAM);
			if (payload_make_pair_setup2(p, NULL) == -1) {
				LOG_ERROR("Error constructing the RTSP pairing request 2");
				goto erexit;
			}
			airplay_rtsp_request_log_debug(p);
			rtspcl_process_request(p->rtspcl, &p->rtsp_request, &p->rtsp_response);

			// Now handle the response and free the response memory
			LOG_DEBUG("Handling RTSP Response for pair-setup step 2");
			p->next_seq = response_handler_pair_setup2(p);
			airplay_rtsp_request_clean(p);
			airplay_session_status_log_debug(p);
			LOG_WARN("Need to free the RTSP response body for pair-setup step 2");
			if (p->rtsp_response.length) {
				if (*p->rtsp_response.content) free(p->rtsp_response.content);
				p->rtsp_response.length = 0;
				LOG_WARN("Freed the RTSP response body for pair-setup step 2");
			}
		}
		else if (p->pair_type == PAIR_CLIENT_HOMEKIT_NORMAL &&
				 p->state == AIRPLAY_STATE_AUTH &&
				 p->next_seq == AIRPLAY_SEQ_PIN_START) {
			// RTSP /pair-pin-start
			if (payload_make_pin_start(p) == -1) {
				LOG_ERROR("Error constructing RTSP /pair-pin-start");
				goto erexit;
			}
			airplay_rtsp_request_log_debug(p);
			rtspcl_process_request(p->rtspcl, &p->rtsp_request, &p->rtsp_response);

			// Now handle the response and free the response memory
			LOG_DEBUG("Handling RTSP Response for pair-pin-start");
			p->next_seq = response_handler_pin_start(p);
			LOG_DEBUG("Cleaning RTSP request");
			airplay_rtsp_request_clean(p);
			LOG_DEBUG("Cleaned RTSP request");
			airplay_session_status_log_info(p);
			LOG_WARN("Need to free the RTSP response body for pair-pin-start");
			if (p->rtsp_response.length) {
				if (*p->rtsp_response.content) {
					LOG_DEBUG("free(p->rtsp_response.content)");
					free(p->rtsp_response.content);
				}
				p->rtsp_response.length = 0;
				LOG_WARN("Freed the RTSP response body for pair-pin-start");
			}
		}
	}
	else {
		LOG_ERROR("Pairing scenario not currently supported.");
		LOG_ERROR("Please open an issue at %s", GITHUB);
		airplay_session_status_log_info(p);
	}

	// RTSP pairing verify for AppleTV
	// if (*p->secret && !rtspcl_pair_verify(p->rtspcl, p->secret)) goto erexit;

	// Send pubkey for MFi devices
	// if (strchr(p->et, '4')) rtspcl_auth_setup(p->rtspcl);
	// if ((p->features & AIRPLAY_FEATURE_SUPPORTS_UNIFIEDPAIRSETUPANDMFI)) {
	// 	rtspcl_auth_setup(p->rtspcl);
	// }

	// build sdp parameter
	// TODO <@bradkeifer> - can probably delete this SDP stuff for AirPlay2
	// buf = strdup(inet_ntoa(peer));
	// sprintf(sdp,
	// 		"v=0\r\n"
	// 		"o=iTunes %s 0 IN IP4 %s\r\n"
	// 		"s=iTunes\r\n"
	// 		"c=IN IP4 %s\r\n"
	// 		"t=0 0\r\n",
	// 		sid, rtspcl_local_ip(p->rtspcl), buf);
	// free(buf);

	// if (!airplaycl_set_sdp(p, sdp)) goto erexit;

	// Create timing service
	p->rtp_ports.time.rport = 0;

	do {
		p->rtp_ports.time.lport = p->port_base + ((port.offset + port.count++) % p->port_range);
		p->rtp_ports.time.fd = open_udp_socket(p->host_addr, &p->rtp_ports.time.lport, true);
	} while (p->rtp_ports.time.fd < 0 && port.count < p->port_range);

	if (p->rtp_ports.time.fd < 0) goto erexit;


	// RTSP SETUP (session)
	if (payload_make_setup_session(p) == -1) {
		LOG_ERROR("Error constructing RTSP SETUP (session)");
		goto erexit;
	}
	airplay_rtsp_request_log_debug(p);
	LOG_DEBUG("rtsp_cipher(%p), AirPlay 2 Client handle(%p)", rtsp_cipher, p);
	rtspcl_process_request(p->rtspcl, &p->rtsp_request, &p->rtsp_response);
	LOG_DEBUG("Implement a response handler for SETUP session");
	airplay_rtsp_request_clean(p);
	if (*p->rtsp_response.content) free(p->rtsp_response.content);


	p->time_running = true;
	pthread_create(&p->time_thread, NULL, _rtp_timing_thread, (void*) p);

	// open RTP sockets, need local ports here before sending SETUP
	// Open Control port
	do {
		p->rtp_ports.ctrl.lport = p->port_base + ((port.offset + port.count++) % p->port_range);
		p->rtp_ports.ctrl.fd = open_udp_socket(p->host_addr, &p->rtp_ports.ctrl.lport, true);
	} while (p->rtp_ports.ctrl.fd < 0 && port.count < p->port_range);
	if (p->rtp_ports.ctrl.fd < 0) goto erexit;

	// Open Audio port
	do {
		p->rtp_ports.audio.lport = p->port_base + ((port.offset + port.count++) % p->port_range);
		p->rtp_ports.audio.fd = open_udp_socket(p->host_addr, &p->rtp_ports.audio.lport, false);
	} while (p->rtp_ports.audio.fd < 0 && port.count < p->port_range);

	if (p->rtp_ports.audio.fd < 0) goto erexit;

	LOG_DEBUG( "[%p]:opened audio socket   l:%5d r:%d", p, p->rtp_ports.audio.lport, p->rtp_ports.audio.rport );
	LOG_DEBUG( "[%p]:opened timing socket  l:%5d r:%d", p, p->rtp_ports.time.lport, p->rtp_ports.time.rport );
	LOG_DEBUG( "[%p]:opened control socket l:%5d r:%d", p, p->rtp_ports.ctrl.lport, p->rtp_ports.ctrl.rport );

	// if (!rtspcl_record(p->rtspcl, p->seq_number + 1, NTP2TS(airplaycl_get_ntp(NULL), p->sample_rate), kd)) goto erexit;

	// if (kd_lookup(kd, "Audio-Latency")) {
	// 	int latency = atoi(kd_lookup(kd, "Audio-Latency"));

	// 	p->latency_frames = max((uint32_t) latency, p->latency_frames);
	// }
	// kd_free(kd);

	p->ctrl_running = true;
	pthread_create(&p->ctrl_thread, NULL, _rtp_control_thread, (void*) p);
	LOG_INFO("Control thread running");

	pthread_mutex_lock(&p->mutex);
	// as connect might take time, state might already have been set
	if (p->raop_state == AIRPLAY_DOWN) p->raop_state = AIRPLAY_FLUSHED;
	pthread_mutex_unlock(&p->mutex);

	// if (set_volume) {
	// 	LOG_INFO("[%p]: setting volume as part of connect %.2f", p, p->volume);
	// 	airplaycl_set_volume(p, p->volume);
	// }

	if (sac) free(sac);
	LOG_DEBUG("Returning true");
	return true;

 erexit:
	if (sac) free(sac);
	kd_free(kd);
	_airplaycl_disconnect(p, true);

	return false;
}

/*----------------------------------------------------------------------------*/
bool _airplaycl_disconnect(struct airplaycl_s *p, bool force)
{
	bool rc = true;

	if (!force && (!p || p->raop_state == AIRPLAY_DOWN)) return true;

	pthread_mutex_lock(&p->mutex);
	p->raop_state = AIRPLAY_DOWN;
	pthread_mutex_unlock(&p->mutex);

	_airplaycl_terminate_rtp(p);

	rc = rtspcl_flush(p->rtspcl, p->seq_number + 1, p->head_ts + 1);
	rc &= rtspcl_disconnect(p->rtspcl);
	rc &= rtspcl_remove_all_exthds(p->rtspcl);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_disconnect(struct airplaycl_s *p)
{
	return _airplaycl_disconnect(p, false);
}

/*----------------------------------------------------------------------------*/
bool airplaycl_destroy(struct airplaycl_s *p)
{
	int i;
	bool rc;

	if (!p) return false;

	rc = airplaycl_disconnect(p);
	rc &= rtspcl_destroy(p->rtspcl);
	pthread_mutex_destroy(&p->mutex);

	for (i = 0; i < MAX_BACKLOG; i++) {
		if (p->backlog[i].buffer) {
			free(p->backlog[i].buffer);
		}
	}

	if (p->alac_codec) alac_delete_encoder(p->alac_codec);

	free(p);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool airplaycl_sanitize(struct airplaycl_s *p)
{
	if (!p) return false;

	pthread_mutex_trylock(&p->mutex);

	p->raop_state = AIRPLAY_DOWN;
	p->head_ts = p->pause_ts = p->start_ts = p->first_ts = 0;
	p->first_pkt = false;
	p->flushing = true;

	pthread_mutex_unlock(&p->mutex);

	return true;
}

/*----------------------------------------------------------------------------*/
// Assess and log the features of the AirPlay2 device
// @param p pointer to the airplay client handle
// @returns true if we can support this device, false if device cannot be supported
// @todo Improve features assessment logic
bool airplaycl_assess_features(struct airplaycl_s *p) {
	int features_map_count = 0;
	uint64_t bitmask;

	features_map_count = sizeof(features_map) / sizeof(struct features_type_map);
	for (int i = 0; i < features_map_count; i++) {
		bitmask = ((uint64_t)1 << features_map[i].bit);
		if (p->features & bitmask) {
			LOG_INFO("%s supports %s. Bit %d, %" PRIX64 "", 
				p->name, features_map[i].name, features_map[i].bit, bitmask);
		}
		else {
			LOG_DEBUG("%s does NOT support %s. Bit %d, %" PRIX64 "", 
				p->name, features_map[i].name, features_map[i].bit, bitmask);
		}
	}

	// Very basic assessment for the moment
	if (p->features & AIRPLAY_FEATURE_SUPPORTS_AUDIO) return true;

	return false;
}

/*----------------------------------------------------------------------------*/
void _airplaycl_send_sync(struct airplaycl_s *airplaycld, bool first)
{
	struct sockaddr_in addr;
	rtp_sync_pkt_t rsp;
	uint64_t now, timestamp;
	int n;

	addr.sin_family = AF_INET;
	addr.sin_addr = airplaycld->peer_addr;
	addr.sin_port = htons(airplaycld->rtp_ports.ctrl.rport);

	// do not send timesync on FLUSHED
	if (airplaycld->raop_state != AIRPLAY_STREAMING) return;

	rsp.hdr.proto = 0x80 | (first ? 0x10 : 0x00);
	rsp.hdr.type = 0x54 | 0x80;
	// seems that seq=7 shall be forced
	rsp.hdr.seq[0] = 0;
	rsp.hdr.seq[1] = 7;

	// first sync is called with mutex locked, so don't block
	if (!first) pthread_mutex_lock(&airplaycld->mutex);

	timestamp = airplaycld->head_ts;
	now = TS2NTP(timestamp, airplaycld->sample_rate);

	// set the NTP time in network order
	rsp.curr_time.seconds = htonl(now >> 32);
	rsp.curr_time.fraction = htonl(now);

	// The DAC time is synchronized with gettime_ms(), minus the latency.
	rsp.rtp_timestamp = htonl(timestamp);
	rsp.rtp_timestamp_latency = htonl(timestamp - airplaycld->latency_frames);

	n = sendto(airplaycld->rtp_ports.ctrl.fd, (void*) &rsp, sizeof(rsp), 0, (void*) &addr, sizeof(addr));

	if (!first) pthread_mutex_unlock(&airplaycld->mutex);

	LOG_DEBUG("[%p]: sync ntp:%u.%u (ts:%" PRIu64 ")", airplaycld, AIRPLAY_SEC(now), AIRPLAY_FRAC(now), airplaycld->head_ts);

	if (n < 0) LOG_ERROR("[%p]: write error: %s", airplaycld, strerror(errno));
	if (n == 0) LOG_INFO("[%p]: write, disconnected on the other end", airplaycld);
}

/*----------------------------------------------------------------------------*/
void *_rtp_timing_thread(void *args)
{
	airplaycl_data_t *airplaycld = (airplaycl_data_t*) args;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_addr = airplaycld->peer_addr;
	addr.sin_port = htons(airplaycld->rtp_ports.time.rport);

	while (airplaycld->time_running)
	{
		rtp_time_pkt_t req;
		struct timeval timeout = { 1, 0 };
		fd_set rfds;
		int n;

		FD_ZERO(&rfds);
		FD_SET(airplaycld->rtp_ports.time.fd, &rfds);

		if ((n = select(airplaycld->rtp_ports.time.fd + 1, &rfds, NULL, NULL, &timeout)) == -1) {
			LOG_ERROR("[%p]: airplaycl_time_connect: socket closed on the other end", airplaycld);
			usleep(100000);
			continue;
		}

		if (!FD_ISSET(airplaycld->rtp_ports.time.fd, &rfds)) continue;

		if (addr.sin_port) {
			n = recv(airplaycld->rtp_ports.time.fd, (void*) &req, sizeof(req), 0);
		}
		else {
			struct sockaddr_in client;
			int len = sizeof(client);
			n = recvfrom(airplaycld->rtp_ports.time.fd, (void*) &req, sizeof(req), 0, (struct sockaddr *)&client, (socklen_t *)&len);
			addr.sin_port = client.sin_port;
			LOG_DEBUG("[%p]: NTP remote port: %d", airplaycld, ntohs(addr.sin_port));
		}

		if( n > 0) 	{
			rtp_time_pkt_t rsp;

			rsp.hdr = req.hdr;
			rsp.hdr.type = 0x53 | 0x80;
			// just copy the request header or set seq=7 and timestamp=0
			rsp.ref_time = req.send_time;
			VALGRIND_MAKE_MEM_DEFINED(&rsp, sizeof(rsp));

			// transform timeval into NTP and set network order
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
			airplaycl_get_ntp(&rsp.recv_time);
#pragma GCC diagnostic pop
#else
			airplaycl_get_ntp(&rsp.recv_time);
#endif

			rsp.recv_time.seconds = htonl(rsp.recv_time.seconds);
			rsp.recv_time.fraction = htonl(rsp.recv_time.fraction);
			rsp.send_time = rsp.recv_time; // might need to add a few fraction ?

			n = sendto(airplaycld->rtp_ports.time.fd, (void*) &rsp, sizeof(rsp), 0, (void*) &addr, sizeof(addr));

			if (n != (int) sizeof(rsp)) {
			   LOG_ERROR("[%p]: error responding to sync", airplaycld);
			}

			LOG_DEBUG( "[%p]: NTP sync: %u.%u (ref %u.%u)", airplaycld, ntohl(rsp.send_time.seconds), ntohl(rsp.send_time.fraction),
															ntohl(rsp.ref_time.seconds), ntohl(rsp.ref_time.fraction) );

		}

		if (n < 0) {
		   LOG_ERROR("[%p]: read error: %s", airplaycld, strerror(errno));
		}

		if (n == 0) {
			LOG_ERROR("[%p]: read, disconnected on the other end", airplaycld);
			usleep(100000);
			continue;
		}
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/
void *_rtp_control_thread(void *args)
{
	airplaycl_data_t *airplaycld = (airplaycl_data_t*) args;

	while (airplaycld->ctrl_running)	{
		struct timeval timeout = { 1, 0 };
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(airplaycld->rtp_ports.ctrl.fd, &rfds);

		if (select(airplaycld->rtp_ports.ctrl.fd + 1, &rfds, NULL, NULL, &timeout) == -1) {
			if (airplaycld->ctrl_running) {
				LOG_ERROR("[%p]: control socket closed", airplaycld);
				airplaycld->sane.ctrl++;
				sleep(1);
			}
			continue;
		}

		if (FD_ISSET(airplaycld->rtp_ports.ctrl.fd, &rfds)) {
			rtp_lost_pkt_t lost;
			int i, n, missed;

			n = recv(airplaycld->rtp_ports.ctrl.fd, (void*) &lost, sizeof(lost), 0);

			if (n < 0) continue;

			lost.seq_number = ntohs(lost.seq_number);
			lost.n = ntohs(lost.n);

			if (n != sizeof(lost)) {
				LOG_ERROR("[%p]: error in received request sn:%d n:%d (recv:%d)",
						  airplaycld, lost.seq_number, lost.n, n);
				lost.n = 0;
				lost.seq_number = 0;
				airplaycld->sane.ctrl++;
			}
			else airplaycld->sane.ctrl = 0;

			pthread_mutex_lock(&airplaycld->mutex);

			for (missed = 0, i = 0; i < lost.n; i++) {
				uint16_t index = (lost.seq_number + i) % MAX_BACKLOG;

				if (airplaycld->backlog[index].seq_number == lost.seq_number + i) {
					struct sockaddr_in addr;
					rtp_header_t *hdr = (rtp_header_t*) airplaycld->backlog[index].buffer;

					// packet have been released meanwhile, be extra cautious
					if (!hdr) {
						missed++;
						continue;
					}

					hdr->proto = 0x80;
					hdr->type = 0x56 | 0x80;
					hdr->seq[0] = 0;
					hdr->seq[1] = 1;

					addr.sin_family = AF_INET;
					addr.sin_addr = airplaycld->peer_addr;
					addr.sin_port = htons(airplaycld->rtp_ports.ctrl.rport);

					airplaycld->retransmit++;

					n = sendto(airplaycld->rtp_ports.ctrl.fd, (void*) hdr,
							   sizeof(rtp_header_t) + airplaycld->backlog[index].size,
							   0, (void*) &addr, sizeof(addr));

					if (n == -1) {
						LOG_WARN("[%p]: error resending lost packet sn:%u (n:%d)",
								   airplaycld, lost.seq_number + i, n);
					}
				}
				else {
					LOG_WARN("[%p]: lost packet out of backlog %u", airplaycld, lost.seq_number + i);
				}
			}

			pthread_mutex_unlock(&airplaycld->mutex);

			LOG_DEBUG("[%p]: retransmit packet sn:%d nb:%d (mis:%d)",
					  airplaycld, lost.seq_number, lost.n, missed);

			continue;
		}

		_airplaycl_send_sync(airplaycld, false);
	}

	return NULL;
}
