/*
 * RAOP : Client to control an AirPlay device, RTSP part
 *
 * Copyright (C) 2004 Shiro Ninomiya <shiron@snino.com>
 * Philippe <philippe_44@outlook.com>
 *
 * See LICENSE
 * 
 */
 
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef USE_CURVE25519
#include "ed25519_signature.h"
#else
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#endif

#include <plist/plist.h>	// Required for AirPlay2 message handlers

#include "platform.h"

#include "aes_ctr.h"
#include "cross_net.h"
#include "cross_util.h"
#include "cross_log.h"
#include "rtsp_client.h"

#define PUBLIC_KEY_SIZE 32
#define SECRET_KEY_SIZE 32
#define PRIVATE_KEY_SIZE 64
#define SIGNATURE_SIZE	64
#define DEFAULT_READ_TIMEOUT 500	// milliseconds

typedef struct rtspcl_s {
    int fd;
    char url[128];
    int cseq;
    key_data_t exthds[MAX_KD];
	char *session;
	const char *useragent;
	struct in_addr local_addr;
	struct {
		char realm[16], nonce[256+1];
		char ha1[32+1];
	} digest;

	// Added for AirPlay2 support
	bool rtsp_response;		// True if we get an RTSP response. False otherwise.
	int status_code;		// The RTSP status code of the response
	char description[256];	// The description of the status code
	int read_timeout;		// ms timeout for reading RTSP Response
	bool cipher_enabled;	// true if RTSP encryption/decryption enabled
	int (*ciphercb)(void *, uint8_t **buf_out, size_t *buf_out_len, uint8_t *buf_in, int buf_in_len, int encrypt);
	void *ciphercb_arg;

} rtspcl_t;

// extern log_level 	raop_loglevel;
// static log_level	*loglevel = &raop_loglevel;

// Seems to be a bug here
extern log_level 	main_log;
static log_level 	*loglevel = &main_log;

static bool exec_request(rtspcl_t *rtspcld, char *cmd, char *content_type,
			 char *content, int length, int get_response, key_data_t *hds,
			 key_data_t *kd, char **resp_content, int *resp_len,
			 char* url);


static bool exec_request_buf(rtspcl_t *rtspcld, char *cmd, char *content_type,
			 char *content, int length, int get_response, key_data_t *hds,
			 key_data_t *kd, char **resp_content, int *resp_len,
			 char* url);

static void rtspcl_process_header_response(rtspcl_t *p, key_data_t *kd, rtsp_response_t *resp);
static void rtspcl_process_body_response(rtspcl_t *p, char *body, size_t len, rtsp_response_t *resp);

static void hexdump(const char *msg, uint8_t *mem, size_t len);

/*----------------------------------------------------------------------------*/
int rtspcl_get_serv_sock(struct rtspcl_s *p) {
	return p->fd;
}

/*----------------------------------------------------------------------------*/
struct rtspcl_s *rtspcl_create(char *useragent) {
	rtspcl_t* rtspcld = malloc(sizeof(rtspcl_t));
	LOG_DEBUG("malloc(rtspcld):%p", rtspcld);
	memset(rtspcld, 0, sizeof(rtspcl_t));
	rtspcld->useragent = useragent;
	rtspcld->fd = -1;
	return rtspcld;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_is_connected(struct rtspcl_s *p) {
	if (p->fd == -1) return false;
	return rtspcl_is_sane(p);
}


/*----------------------------------------------------------------------------*/
bool rtspcl_is_sane(struct rtspcl_s *p) {
	struct pollfd pfds;

	pfds.fd = p->fd;
	pfds.events = POLLIN;

	if (p->fd == -1) return true;

	int n = poll(&pfds, 1, 0);
	if (n == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;

	return true;
}

/*----------------------------------------------------------------------------*/
// Connect to the RTSP server and setup internal data structures
// @param p RTSP client handle. p->url set to be the RTSP URL
// @param local local IP address details
// @param host AirPlay device IP address details
// @param destport AirPlay device port to open for RTSP connection
// @param sid session id defined in the RTSP URL
// @return true on success, false on failure
bool rtspcl_connect(struct rtspcl_s *p, struct in_addr local, struct in_addr host, uint16_t destport, char *sid) {
	if (!p) return false;

	p->session = NULL;
	if ((p->fd = open_tcp_socket(local, NULL, true)) == -1) return false;
	if (!tcp_connect_by_host(p->fd, host, destport)) return false;

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);

	getsockname(p->fd, (struct sockaddr*)&name, &namelen);
	memcpy(&p->local_addr,&name.sin_addr, sizeof(struct in_addr));

	sprintf(p->url,"rtsp://%s/%s", inet_ntoa(host), sid);

	p->read_timeout = DEFAULT_READ_TIMEOUT;	// todo - make this a configurable variable

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_disconnect(struct rtspcl_s *p) {
	if (!p) return false;

	bool rc = true;

	if (p->fd != -1) {
		rc = exec_request(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL);
		closesocket(p->fd);
	}

	if (p->session) free(p->session);
	p->session = NULL;
	p->fd = -1;

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_destroy(struct rtspcl_s *p) {
	if (!p) return false;

	bool rc = rtspcl_disconnect(p);
	LOG_DEBUG("free(p):%p", p);
	free(p);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_add_exthds(struct rtspcl_s *p, char *key, char *data) {
	if (!p) return false;

	int i = 0;

	while (p->exthds[i].key && i < MAX_KD - 1) {
		if ((unsigned char) p->exthds[i].key[0] == 0xff) break;
		i++;
	}

	if (i == MAX_KD - 2) return false;

	if (p->exthds[i].key) {
		free(p->exthds[i].key);
		free(p->exthds[i].data);
	} else p->exthds[i + 1].key = NULL;

	p->exthds[i].key = strdup(key);
	p->exthds[i].data = strdup(data);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_mark_del_exthds(struct rtspcl_s *p, char *key) {
	if (!p) return false;

	for (int i = 0; p->exthds[i].key; i++) {
		if (!strcmp(key, p->exthds[i].key)){
			p->exthds[i].key[0]=0xff;
			return true;
		}
	}

	return false;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_remove_all_exthds(struct rtspcl_s *p) {
	if (!p) return false;

	for (int i = 0; p->exthds[i].key; i++) {
		free(p->exthds[i].key);
		free(p->exthds[i].data);
	}

	memset(p->exthds, 0, sizeof(p->exthds));

	return true;
}

/*----------------------------------------------------------------------------*/
char* rtspcl_local_ip(struct rtspcl_s *p) {
	if (!p) return NULL;

	static char buf[16];
	return strcpy(buf, inet_ntoa(p->local_addr));
}

/*----------------------------------------------------------------------------*/
bool rtspcl_announce_sdp(struct rtspcl_s *p, char *sdp, char *passwd) {
	if(!p) return false;

	if (passwd && *passwd) {
		char* auth;
		key_data_t kd[MAX_KD] = { 0 };

		// execute an announce request and parse the output to get realm and nonce
		exec_request(p, "ANNOUNCE", "application/sdp", sdp, 0, 2, NULL, kd, NULL, NULL, NULL);

		if ((auth = kd_lookup(kd, "WWW-Authenticate")) != NULL) {
			char * buf;

			if ((buf = strcasestr(auth, "realm")) != NULL) sscanf(buf, "realm%*[^\"]\"%16[^\"]", p->digest.realm);
			if ((buf = strcasestr(auth, "nonce")) != NULL) sscanf(buf, "nonce%*[^\"]\"%256[^\"]", p->digest.nonce);

			// so that we don't keep password in memory
			asprintf(&buf, "%s:%s:%s", !strcasecmp(p->digest.realm, "raop") ? "iTunes" : "AirPlay", p->digest.realm, passwd);

			uint8_t ha1_bin[16];
			MD5((uint8_t*) buf, strlen(buf), ha1_bin);
			free(buf); buf = (char*) p->digest.ha1;
			bytes2hex(ha1_bin, sizeof(ha1_bin), &buf);
		}

		kd_free(kd);
	}

	return exec_request(p, "ANNOUNCE", "application/sdp", sdp, 0, 1, NULL, NULL, NULL, NULL, NULL);
}

/*----------------------------------------------------------------------------*/
bool rtspcl_setup(struct rtspcl_s *p, struct rtp_port_s *port, key_data_t *rkd) {
	key_data_t hds[2];
	char *temp;

	if (!p) return false;

	port->audio.rport = 0;

	hds[0].key = "Transport";
	(void)! asprintf(&hds[0].data, "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=%d;timing_port=%d",
							(unsigned) port->ctrl.lport, (unsigned) port->time.lport);
	if (!hds[0].data) return false;
	hds[1].key = NULL;

	if (!exec_request(p, "SETUP", NULL, NULL, 0, 1, hds, rkd, NULL, NULL, NULL)) return false;
	free(hds[0].data);

	if ((temp = kd_lookup(rkd, "Session")) != NULL) {
		p->session = strdup(strtrim(temp));
		LOG_DEBUG("[%p]: <------ : session:%s", p, p->session);
		return true;
	}
	else {
		kd_free(rkd);
		LOG_ERROR("[%p]: no session in response", p);
		return false;
	}
}

/*----------------------------------------------------------------------------*/
bool rtspcl_record(struct rtspcl_s *p, uint16_t start_seq, uint32_t start_ts, key_data_t *rkd) {
	if (!p) return false;

	if (!p->session){
		LOG_ERROR("[%p]: no session in progress", p);
		return false;
	}

	key_data_t hds[3];

	hds[0].key 	= "Range";
	hds[0].data = "npt=0-";
	hds[1].key 	= "RTP-Info";
	(void)! asprintf(&hds[1].data, "seq=%u;rtptime=%u", (unsigned) start_seq, (unsigned) start_ts);
	if (!hds[1].data) return false;
	hds[2].key	= NULL;

	bool rc = exec_request(p, "RECORD", NULL, NULL, 0, 1, hds, rkd, NULL, NULL, NULL);
	free(hds[1].data);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_set_parameter(struct rtspcl_s *p, char *param) {
	if (!p) return false;
	return exec_request(p, "SET_PARAMETER", "text/parameters", param, 0, 1, NULL, NULL, NULL, NULL, NULL);
}

/*----------------------------------------------------------------------------*/
bool rtspcl_set_artwork(struct rtspcl_s *p, uint32_t timestamp, char *content_type, int size, char *image) {
	if (!p) return false;

	key_data_t hds[2];
	char rtptime[20];

	sprintf(rtptime, "rtptime=%u", timestamp);

	hds[0].key	= "RTP-Info";
	hds[0].data	= rtptime;
	hds[1].key	= NULL;

	return exec_request(p, "SET_PARAMETER", content_type, image, size, 2, hds, NULL, NULL, NULL, NULL);
}

/*----------------------------------------------------------------------------*/
bool rtspcl_set_daap(struct rtspcl_s *p, uint32_t timestamp, int count, va_list args) {
	if (!p) return false;

	key_data_t hds[2];
	char rtptime[20];
	char* q, * str;

	str = q = malloc(1024);
	if (!str) return false;

	sprintf(rtptime, "rtptime=%u", timestamp);

	hds[0].key	= "RTP-Info";
	hds[0].data	= rtptime;
	hds[1].key	= NULL;

	// set mandatory headers first, the final size will be set at the end
	q = (char*) memcpy(q, "mlit", 4) + 8;
	q = (char*) memcpy(q, "mikd", 4) + 4;
	for (int i = 0; i < 3; i++) { *q++ = 0; } *q++ = 1;
	*q++ = 2;

	while (count-- && (q-str) < 1024) {
		char *fmt, type;
		uint32_t size;

		fmt = va_arg(args, char*);
		type = (char) va_arg(args, int);
		q = (char*) memcpy(q, fmt, 4) + 4;

		switch(type) {
			case 's': {
				char *data;

				data = va_arg(args, char*);
				size = strlen(data);
				for (int i = 0; i < 4; i++) *q++ = size >> (24-8*i);
				q = (char*) memcpy(q, data, size) + size;
				break;
			}
			case 'i': {
				int data;
				data = va_arg(args, int);
				for (int i = 0; i < 3; i++) { *q++ = 0; } *q++ = 2;
				*q++ = (data >> 8); *q++ = data;
				break;
			}
		}
	}

	// set "mlit" object size
	for (int i = 0; i < 4; i++) *(str + 4 + i) = (q-str-8) >> (24-8*i);

	bool rc = exec_request(p, "SET_PARAMETER", "application/x-dmap-tagged", str, q-str, 2, hds, NULL, NULL, NULL, NULL);
	free(str);
	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd) {
	if (!p) return false;
	return exec_request(p, "OPTIONS", NULL, NULL, 0, 1, NULL, rkd, NULL, NULL, "*");
}

/*----------------------------------------------------------------------------*/
bool rtspcl_pair_verify(struct rtspcl_s *p, char *secret_hex) {
	uint8_t auth_pub[PUBLIC_KEY_SIZE], auth_priv[PRIVATE_KEY_SIZE];
	uint8_t verify_pub[PUBLIC_KEY_SIZE], verify_secret[SECRET_KEY_SIZE];
	uint8_t atv_pub[PUBLIC_KEY_SIZE], *atv_data;
	uint8_t secret[SECRET_KEY_SIZE], shared_secret[SECRET_KEY_SIZE];
	uint8_t signed_keys[SIGNATURE_SIZE];
	uint8_t *buf, *content;
	SHA512_CTX digest;
	uint8_t aes_key[16], aes_iv[16];
	aes_ctr_context ctx;
	int atv_len, len;
	bool rc = true;

	if (!p) return false;
	buf = secret;
	hex2bytes(secret_hex, &buf);

	// retrieve authentication keys from secret
#ifdef USE_CURVE25519
	ed25519_CreateKeyPair(auth_pub, auth_priv, NULL, secret);
#else
	EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, secret, SECRET_KEY_SIZE);
	size_t size = SECRET_KEY_SIZE;
	EVP_PKEY_get_raw_private_key(priv_key, auth_priv, &size);
	EVP_PKEY_get_raw_public_key(priv_key, auth_priv + SECRET_KEY_SIZE, &size);
	EVP_PKEY_get_raw_public_key(priv_key, auth_pub, &size);
	EVP_PKEY_free(priv_key);
#endif
	// create a verification public key
	RAND_bytes(verify_secret, SECRET_KEY_SIZE);
	VALGRIND_MAKE_MEM_DEFINED(verify_secret, SECRET_KEY_SIZE);
#ifdef USE_CURVE25519
	curve25519_dh_CalculatePublicKey(verify_pub, verify_secret);
#else
	priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, verify_secret, SECRET_KEY_SIZE);
	size = PUBLIC_KEY_SIZE;
	EVP_PKEY_get_raw_public_key(priv_key, verify_pub, &size);
	EVP_PKEY_free(priv_key);
#endif

	// POST the auth_pub and verify_pub concataned
	buf = malloc(4 + PUBLIC_KEY_SIZE * 2);
	len = 0;
	memcpy(buf, "\x01\x00\x00\x00", 4); len += 4;
	memcpy(buf + len, verify_pub, PUBLIC_KEY_SIZE); len += PUBLIC_KEY_SIZE;
	memcpy(buf + len, auth_pub, PUBLIC_KEY_SIZE); len += PUBLIC_KEY_SIZE;

	if (!exec_request(p, "POST", "application/octet-stream", (char*) buf, len, 1, NULL, NULL, (char**) &content, &atv_len, "/pair-verify")) {
		LOG_ERROR("[%p]: AppleTV verify step 1 failed (pair again)", p);
		free(buf);
		return false;
	}

	// get atv_pub and atv_data then create shared secret
	memcpy(atv_pub, content, PUBLIC_KEY_SIZE);
	atv_data = malloc(atv_len - PUBLIC_KEY_SIZE);
	memcpy(atv_data, content + PUBLIC_KEY_SIZE, atv_len - PUBLIC_KEY_SIZE);
#ifdef USE_CURVE25519
	curve25519_dh_CreateSharedKey(shared_secret, atv_pub, verify_secret);
#else	
	priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, verify_secret, SECRET_KEY_SIZE);
	EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, atv_pub, PUBLIC_KEY_SIZE);
	EVP_PKEY_CTX* evp_ctx = EVP_PKEY_CTX_new(priv_key, NULL);
	EVP_PKEY_derive_init(evp_ctx);
	EVP_PKEY_derive_set_peer(evp_ctx, peer_key);
	size = SECRET_KEY_SIZE;
	EVP_PKEY_derive(evp_ctx, shared_secret, &size);
	EVP_PKEY_CTX_free(evp_ctx);
	EVP_PKEY_free(peer_key);
	EVP_PKEY_free(priv_key);
#endif
	free(content);

	// build AES-key & AES-iv from shared secret digest
	SHA512_Init(&digest);
	SHA512_Update(&digest, "Pair-Verify-AES-Key", strlen("Pair-Verify-AES-Key"));
	SHA512_Update(&digest, shared_secret, SECRET_KEY_SIZE);
	SHA512_Final(buf, &digest);
	memcpy(aes_key, buf, 16);

	SHA512_Init(&digest);
	SHA512_Update(&digest, "Pair-Verify-AES-IV", strlen("Pair-Verify-AES-IV"));
	SHA512_Update(&digest, shared_secret, SECRET_KEY_SIZE);
	SHA512_Final(buf, &digest);
	memcpy(aes_iv, buf, 16);

	// sign the verify_pub and atv_pub
	memcpy(buf, verify_pub, PUBLIC_KEY_SIZE);
	memcpy(buf + PUBLIC_KEY_SIZE, atv_pub, PUBLIC_KEY_SIZE);
#ifdef USE_CURVE25519
	ed25519_SignMessage(signed_keys, auth_priv, NULL, buf, PUBLIC_KEY_SIZE * 2);
#else
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, auth_priv, SECRET_KEY_SIZE);
	EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, priv_key);
	size = SIGNATURE_SIZE;
	EVP_DigestSign(md_ctx, signed_keys, &size, buf, SIGNATURE_SIZE);
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(priv_key);
#endif

	// encrypt the signed result + atv_data, add 4 NULL bytes at the beginning
	aes_ctr_init(&ctx, aes_key, aes_iv, CTR_BIG_ENDIAN);
	memcpy(buf, atv_data, atv_len - PUBLIC_KEY_SIZE);
	aes_ctr_encrypt(&ctx, buf, atv_len - PUBLIC_KEY_SIZE);
	memcpy(buf + 4, signed_keys, SIGNATURE_SIZE);
	aes_ctr_encrypt(&ctx, buf + 4, SIGNATURE_SIZE);
	memcpy(buf, "\x00\x00\x00\x00", 4);
	len = SIGNATURE_SIZE + 4;
	free(atv_data);

	if (!exec_request(p, "POST", "application/octet-stream", (char*) buf, len, 1, NULL, NULL, NULL, NULL, "/pair-verify")) {
		LOG_ERROR("[%p]: AppleTV verify step 2 failed (pair again)", p);
		rc = false;
	}

	free(buf);

	return rc;
}

/*----------------------------------------------------------------------------*/
/* This comment from owntone codebase
The purpose of auth-setup is to authenticate the device and to exchange keys
for encryption. We don't do that, but some AirPlay 2 speakers (Sonos beam,
Airport Express fw 7.8) require this step anyway, otherwise we get a 403 to
our ANNOUNCE. So we do it with a flag for no encryption, and without actually
authenticating the device.

Good to know (source Apple's MFi Accessory Interface Specification):
- Curve25519 Elliptic-Curve Diffie-Hellman technology for key exchange
- RSA for signing and verifying and AES-128 in counter mode for encryption
- We start by sending a Curve25519 public key + no encryption flag
- The device responds with public key, MFi certificate and a signature, which
  is created by the device signing the two public keys with its RSA private
  key and then encrypting the result with the AES master key derived from the
  Curve25519 shared secret (generated from device private key and our public
  key)
- The AES key derived from the Curve25519 shared secret can then be used to
  encrypt future content
- New keys should be generated for each authentication attempt, but we don't
  do that because we don't really use this + it adds a libsodium dependency

Since we don't do auth nor encryption, we currently just ignore the reponse.
*/

bool rtspcl_auth_setup(struct rtspcl_s *p) {
	if (!p) return false;

	uint8_t secret[SECRET_KEY_SIZE], * pub_key = malloc(PUBLIC_KEY_SIZE + 1);
	uint8_t* rsp;
	int rsp_len;

	// create a verification public key
	RAND_bytes(secret, SECRET_KEY_SIZE);
	VALGRIND_MAKE_MEM_DEFINED(secret, SECRET_KEY_SIZE);
#ifdef USE_CURVE25519
	curve25519_dh_CalculatePublicKey(pub_key + 1, secret);
#else
	EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret, 32);
	size_t size = PUBLIC_KEY_SIZE;
	EVP_PKEY_get_raw_public_key(key, pub_key + 1, &size);
	EVP_PKEY_free(key);
#endif
	// POST the auth_pub and verify_pub concataned
	pub_key[0] = '\x01';

	if (!exec_request(p, "POST", "application/octet-stream", (char*) pub_key,
					  PUBLIC_KEY_SIZE+1, 1, NULL, NULL, (char**) &rsp, &rsp_len, "/auth-setup")) {
		LOG_ERROR("[%p]: auth-setup failed", p);
		free(pub_key);
		return false;
	}

	free(pub_key);
	free(rsp);

	return true;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_flush(struct rtspcl_s *p, uint16_t seq_number, uint32_t timestamp) {
	if(!p) return false;

	bool rc;
	key_data_t hds[2];

	hds[0].key	= "RTP-Info";
	(void)! asprintf(&hds[0].data, "seq=%u;rtptime=%u", (unsigned) seq_number, (unsigned) timestamp);
	if (!hds[0].data) return false;
	hds[1].key	= NULL;

	rc = exec_request(p, "FLUSH", NULL, NULL, 0, 1, hds, NULL, NULL, NULL, NULL);
	free(hds[0].data);

	return rc;
}

/*----------------------------------------------------------------------------*/
bool rtspcl_teardown(struct rtspcl_s *p) {
	if (!p) return false;
	return exec_request(p, "TEARDOWN", NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL);
}

/*
 * send RTSP request, and get response if it's needed
 * if this gets a success, *rkd is allocated or reallocated (if *kd is not NULL)
 */
static bool exec_request(struct rtspcl_s *rtspcld, char *cmd, char *content_type,
				char *content, int length, int get_response, key_data_t *hds,
				key_data_t *rkd, char **resp_content, int *resp_len, char* url) {
	char line[2048] = "";
	char *req;
	char buf[128];
	const char delimiters[] = " ";
	char *token,*dp;
	int i, rval, len, clen;
	int timeout = 10000; // msec unit
	struct pollfd pfds;
	key_data_t lkd[MAX_KD], *pkd;

	rtspcld->rtsp_response = false;
	rtspcld->status_code = 0;
	rtspcld->description[0] = 0;

	if (!rtspcld || rtspcld->fd == -1) return false;

	pfds.fd = rtspcld->fd;
	pfds.events = POLLOUT;

	i = poll(&pfds, 1, 0);
	if (i == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;

	if ((req = malloc(4096+length)) == NULL) return false;
	LOG_DEBUG("malloc(req):%p", req);

	sprintf(req, "%s %s RTSP/1.0\r\n",cmd, url ? url : rtspcld->url);

	for (i = 0; hds && hds[i].key != NULL; i++) {
		sprintf(buf, "%s: %s\r\n", hds[i].key, hds[i].data);
		strcat(req, buf);
	}

	if (content_type && content) {
		sprintf(buf, "Content-Type: %s\r\nContent-Length: %d\r\n", content_type, length ? length : (int) strlen(content));
		strcat(req, buf);
	}

	sprintf(buf,"CSeq: %d\r\n", ++rtspcld->cseq);
	strcat(req, buf);

	sprintf(buf, "User-Agent: %s\r\n", rtspcld->useragent );
	strcat(req, buf);

	for (i = 0; rtspcld->exthds[i].key; i++) {
		if ((unsigned char) rtspcld->exthds[i].key[0] == 0xff) continue;
		sprintf(buf,"%s: %s\r\n", rtspcld->exthds[i].key, rtspcld->exthds[i].data);
		strcat(req, buf);
	}

	if (rtspcld->session != NULL )    {
		sprintf(buf,"Session: %s\r\n",rtspcld->session);
		strcat(req, buf);
	}

	// add digest if we have a password
	if (*rtspcld->digest.ha1) {
		char* buf, digest[32+1];
		asprintf(&buf, "%s:%s", cmd, url ? url : rtspcld->url);
		unsigned char ha2_bin[16], ha2[32+1];
		MD5((uint8_t*) buf, strlen(buf), ha2_bin);

		free(buf); buf = (char*) ha2;
		bytes2hex(ha2_bin, sizeof(ha2_bin), &buf);
		asprintf(&buf, "%s:%s:%s", rtspcld->digest.ha1, rtspcld->digest.nonce, ha2);
		unsigned char digest_bin[16];
		MD5((uint8_t*) buf, strlen(buf), digest_bin);

		free(buf); buf = digest;
		bytes2hex(digest_bin, sizeof(digest_bin), &buf);

		sprintf(req + strlen(req), "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n", 
			!strcasecmp(rtspcld->digest.realm, "raop") ? "iTunes" : "AirPlay", rtspcld->digest.realm,
			rtspcld->digest.nonce, url ? url : rtspcld->url, digest);
	}

	strcat(req,"\r\n");
	len = strlen(req);

	if (content_type && content) {
		len += (length ? length : strlen(content));
		memcpy(req + strlen(req), content, length ? length : strlen(content));
		req[len] = '\0';
	}

	rval = send(rtspcld->fd, req, len, 0);
	LOG_DEBUG( "[%p]: ----> : write %s", rtspcld, req );
	LOG_DEBUG("Wrote %d bytes", rval);
	LOG_DEBUG("free(req):%p", req);
	free(req);

	if (rval != len) {
	   LOG_ERROR( "[%p]: couldn't write request (%d!=%d)", rtspcld, rval, len );
	}

	if (!get_response)
		return true;

	if (http_read_line(rtspcld->fd, line, sizeof(line), timeout, true) <= 0) {
		LOG_ERROR("[%p]: response : %s request failed", rtspcld, line);
		if (get_response == 1) return false;
		else return true;
	}

	token = strtok(line, delimiters);
	LOG_DEBUG("token should be RTSP/1.0: %s", token);
	if (!strncmp(token, "RTSP/1.0", strlen("RTSP/1.0"))) {
		rtspcld->rtsp_response = true;
		LOG_DEBUG("Valid RTSP/1.0 Response");
	}
	token = strtok(NULL, delimiters);

	if (token == NULL || strcmp(token, "200")) {
		LOG_ERROR("[%p]: <------ : request failed, error %s", rtspcld, line);
		if (get_response == 1) {
			if (token) {
				rtspcld->status_code = (int)strtol(token, NULL, 10);
				while ((token = strtok(NULL, delimiters))) {
					if ((strlen(rtspcld->description) + 
						strlen(token) < sizeof(rtspcld->description)))
					strcat(rtspcld->description, token);
				}
			}
			return false;
		}
	} else {
		LOG_DEBUG("[%p]: <------ : %s: request ok", rtspcld, token);
		rtspcld->status_code = (int)strtol(token, NULL, 10);
		while ((token = strtok(NULL, delimiters))) {
			if ((strlen(rtspcld->description) + 
				strlen(token) < sizeof(rtspcld->description)))
			strcat(rtspcld->description, token);
		}
	}

	i = 0;
	clen = 0;
	if (rkd) pkd = rkd;
	else pkd = lkd;
	pkd[0].key = NULL;

	while (http_read_line(rtspcld->fd, line, sizeof(line), timeout, true) > 0) {
		LOG_DEBUG("[%p]: <------ : %s", rtspcld, line);
		timeout = 1000; // once it started, it shouldn't take a long time

		if (i && line[0] == ' ') {
			size_t j;
			for(j = 0; j < strlen(line); j++) if (line[j] != ' ') break;
			pkd[i].data = strdup(line + j);
			continue;
		}

		dp = strstr(line,":");

		if (!dp){
			LOG_ERROR("[%p]: Request failed, bad header", rtspcld);
			kd_free(pkd);
			return false;
		}

		*dp = 0;
		pkd[i].key = strdup(line);
		pkd[i].data = strdup(dp + 1);

		if (!strcasecmp(pkd[i].key, "Content-Length")) clen = atol(pkd[i].data);

		i++;
		pkd[i].key = NULL;
	}

	if (clen) {
		char *data = malloc(clen);
		LOG_DEBUG("malloc(data):%p", data);
		int size = 0;

		while (data && size < clen) {
			int bytes = recv(rtspcld->fd, data + size, clen - size, 0);
			if (bytes <= 0) break;
			size += bytes;
		}

		if (!data || size != clen) {
			LOG_ERROR("[%p]: content length receive error %p %d", rtspcld, data, size);
		}

		if (*loglevel >= lDEBUG) logdump(data, clen);

		if (resp_content) {
			*resp_content = data;
			if (resp_len) *resp_len = clen;
		} 
		else {
			LOG_DEBUG("free(data):%p", data);
			free(data);
		}
	}

	pkd[i].key = NULL;
	if (!rkd) kd_free(pkd);

	return true;
}

// AirPlay2 specific RTSP handlers

// send RTSP request, and get response if it's needed. Ciphering of the exchange is supported
// if this gets a success, *rkd is allocated or reallocated (if *kd is not NULL)
// @param rtspcld the RTSP session handle
// @param cmd the RTSP Request Command
// @param content_type the RTSP Content-Type. Can be NULL if no content.
// @param content the RTSP Request (body) content. Can be NULL
// @param length the RTSP Request (body) content length. 
// Must be the length of the content in bytes, if content is non-NULL. Can be 0 if content is NULL.
// @param get_response 1 to read the RTSP Response, 0 to not read any RTSP Response
// @param hds RTSP Header key data items specific to this RTSP Request.
// @param rkd RTSP Header key data items from the RTSP Response - if desired. Can be NULL 
// and indicates that no Header key data items are required by the caller
// @param resp_content a pointer to where the RTSP Response (body) content is to be saved. Can be NULL
// and indicates that no RTSP Response (body) content is required by the caller
// @param resp_len a pointer to where the RTSP Response (body) content length is to be saved. Can be NULL
// and indicates that no RTSP Response (body) content is required by the caller
// @param url a custom/specific URL to use instead of the standard URL used for this specific RTSP session handle.
// Can be NULL
// @returns true on success, false on failure
// @note Header key data items that are generic to every RTSP Request associated with the RTSP
// session handle are stored in the RTSP session handle. CSeq is automatically
// calculated and managed internally by this function
static bool exec_request_buf(struct rtspcl_s *rtspcld, char *cmd, char *content_type,
				char *content, int length, int get_response, key_data_t *hds,
				key_data_t *rkd, char **resp_content, int *resp_len, char* url) {

	char resp_line[2048] = "";
	char *line;
	char buf[512];
	const char delimiters[] = " ";
	const char buf_plaintext_delimiters[] = "\r\n";
	char *token,*dp;
	int i, rval, len, clen;
	// int timeout = 10000; // msec unit
	struct pollfd pfds;
	key_data_t lkd[MAX_KD];
	key_data_t *pkd = NULL;
	uint8_t *buf_plaintext = NULL;
	size_t len_plaintext = 0;
	uint8_t *buf_raw = NULL;
	size_t len_raw = 0;
	uint8_t *response_body = NULL;
	char *response_header = NULL;
	char *temp_buf = NULL;
	char *needle = NULL;
	char *needle_ptr = NULL;
	char *header_ptr = NULL;
	char *line_ptr = NULL;
	float cipher_ratio = 0.0;

	rtspcld->rtsp_response = false;
	rtspcld->status_code = 0;
	rtspcld->description[0] = 0;

	if (!rtspcld || rtspcld->fd == -1) {
		LOG_ERROR("Invalid RTSP Client Handle (%p) or RTSP file descriptor (%d)",
			rtspcld, rtspcld->fd);
		return false;
	}

	pfds.fd = rtspcld->fd;
	pfds.events = POLLOUT;

	i = poll(&pfds, 1, 0);
	if (i == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;

	// Allocate memory buffers for plain text and encrypted data. Maxmimum RTSP Message size is 4096 bytes
	// Presumably this is also enough for encrypted exchanges?? - Perhaps not.
	// @todo check and validate sizing requirements for encrypted data
	buf_plaintext = malloc(RTSP_MAX_MESSAGE);
	if (!buf_plaintext) {
		LOG_ERROR("Unable to allocate output plaintext memory. %s", strerror(errno));
		goto erexit;
	}
	LOG_DEBUG("malloc(buf_plaintext):%d, %p", RTSP_MAX_MESSAGE, buf_plaintext);
	memset(buf_plaintext, 0, RTSP_MAX_MESSAGE);
	buf_raw = malloc((int)( (float)CIPHER_RATIO * (float)RTSP_MAX_MESSAGE));
	if (!buf_raw) {
		LOG_ERROR("Unable to allocate output raw memory. %s", strerror(errno));
		goto erexit;
	}
	LOG_DEBUG("malloc(buf_raw):%d, %p", (size_t)( (float)CIPHER_RATIO * (float)RTSP_MAX_MESSAGE), buf_raw);
	memset(buf_raw, 0, (size_t)( (float)CIPHER_RATIO * (float)RTSP_MAX_MESSAGE));
	

	sprintf((char *)buf_plaintext, "%s %s RTSP/1.0\r\n",cmd, url ? url : rtspcld->url);

	for (i = 0; hds && hds[i].key != NULL; i++) {
		sprintf(buf, "%s: %s\r\n", hds[i].key, hds[i].data);
		strcat((char *)buf_plaintext, buf);
	}

	if (content_type && content) {
		sprintf(buf, "Content-Type: %s\r\nContent-Length: %d\r\n", content_type, length);
		strcat((char *)buf_plaintext, buf);
	}

	sprintf(buf,"CSeq: %d\r\n", ++rtspcld->cseq);
	strcat((char *)buf_plaintext, buf);

	sprintf(buf, "User-Agent: %s\r\n", rtspcld->useragent );
	strcat((char *)buf_plaintext, buf);

	for (i = 0; rtspcld->exthds[i].key; i++) {
		if ((unsigned char) rtspcld->exthds[i].key[0] == 0xff) continue;
		sprintf(buf,"%s: %s\r\n", rtspcld->exthds[i].key, rtspcld->exthds[i].data);
		strcat((char *)buf_plaintext, buf);
	}

	if (rtspcld->session != NULL )    {
		sprintf(buf,"Session: %s\r\n",rtspcld->session);
		strcat((char *)buf_plaintext, buf);
	}

	// add digest if we have a password
	if (*rtspcld->digest.ha1) {
		char* buf_digest, digest[32+1];
		asprintf(&buf_digest, "%s:%s", cmd, url ? url : rtspcld->url);
		unsigned char ha2_bin[16], ha2[32+1];
		MD5((uint8_t*) buf_digest, strlen(buf_digest), ha2_bin);

		free(buf_digest); buf_digest = (char*) ha2;
		bytes2hex(ha2_bin, sizeof(ha2_bin), &buf_digest);
		asprintf(&buf_digest, "%s:%s:%s", rtspcld->digest.ha1, rtspcld->digest.nonce, ha2);
		unsigned char digest_bin[16];
		MD5((uint8_t*) buf_digest, strlen(buf_digest), digest_bin);

		free(buf_digest); buf_digest = digest;
		bytes2hex(digest_bin, sizeof(digest_bin), &buf_digest);

		sprintf((char *)buf_plaintext + strlen((char *)buf_plaintext), 
			"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n", 
			!strcasecmp(rtspcld->digest.realm, "raop") ? "iTunes" : "AirPlay", rtspcld->digest.realm,
			rtspcld->digest.nonce, url ? url : rtspcld->url, digest);
	}

	strcat((char *)buf_plaintext,"\r\n");
	len = strlen((char *)buf_plaintext);
	len_plaintext = len;

	if (content_type && content) {
		len_plaintext = len + length;
		memcpy(buf_plaintext + len, content, length);
	}

#if AIRPLAY_DUMP_TRAFFIC
	hexdump("RTSP Request - Plaintext\n", buf_plaintext, len_plaintext);
#endif
	if (rtspcld->cipher_enabled) {
		// NOTE: Must free(buf_raw) pre-decryption, because callback allocates the required memory
		LOG_DEBUG("free(buf_raw):%p", buf_raw);
		free(buf_raw);
		LOG_DEBUG("Encrypting into buf_raw(%p)", buf_raw);
		rtspcld->ciphercb(rtspcld->ciphercb_arg, &buf_raw, &len_raw, buf_plaintext, len_plaintext, 1);
		LOG_DEBUG("buf_raw after encryption(%p)", buf_raw);
		cipher_ratio = (float)len_raw/(float)len_plaintext;
		LOG_DEBUG("Cipher Ratio: %0.2f", cipher_ratio);
		if (cipher_ratio > CIPHER_RATIO) {
			LOG_ERROR("Actual Cipher Ratio (%0.2f) exceeds assumed (%0.2f)", cipher_ratio, CIPHER_RATIO);
			LOG_ERROR("Please raise a github issue at %s", GITHUB);
		}
	}
	else {
		LOG_DEBUG("Encryption not required. Copying %d bytes to buf_raw", len_plaintext);
		memcpy(buf_raw, buf_plaintext, len_plaintext);
		len_raw = len_plaintext;
	}
	LOG_DEBUG("Sending %zu bytes of %s data", len_raw, rtspcld->cipher_enabled ? "encrypted" : "plain text");
#if AIRPLAY_DUMP_TRAFFIC
	hexdump("RTSP Request - Raw\n", buf_raw, len_raw);
#endif
	rval = send(rtspcld->fd, buf_raw, len_raw, 0);
	if (rval != len_raw) {
	   LOG_ERROR( "[%p]: couldn't write request (%d!=%d)", rtspcld, rval, len_raw);
	}

	if (!get_response) {
		// Free allocated memory and return true.
		if (buf_plaintext) {
			LOG_DEBUG("free(buf_plaintext):%p due to no get_response", buf_plaintext);
			free(buf_plaintext);
		}
		if (buf_raw) {
			LOG_DEBUG("free(buf_raw):%p due to no get_response", buf_raw);
			free(buf_raw);
		}
		return true;
	}

	// Zero data transfer buffers in preparation for receiving RTSP Response just to be safe
	// valgrind complains about the below statement with "nvalid write of size 8"
	// memset(buf_raw, 0, (size_t)( (float)CIPHER_RATIO * (float)RTSP_MAX_MESSAGE));
	// len_raw = 0;
	// memset(buf_plaintext, 0, RTSP_MAX_MESSAGE);
	// len_plaintext = 0;

	pfds.fd = rtspcld->fd;
	pfds.events = POLLIN;
	LOG_DEBUG("Starting polled read of RTSP Response, with timeout of %d ms", rtspcld->read_timeout);
	for (len_raw=0; len_raw < RTSP_MAX_MESSAGE; len_raw++) {
		if (poll(&pfds, 1, rtspcld->read_timeout)) {
			rval = recv(rtspcld->fd, buf_raw + len_raw, 1, 0);
			if (rval == 0) {
				if (len_raw == 0) {
					LOG_ERROR("No response from AirPlay client");
					goto erexit;
				}
				break;
			}
			else if (rval == -1) {
				LOG_ERROR("Unexpected error reading RTSP Response. %s", strerror(errno));
				goto erexit;
			}
		}
		else {
			break;
		}
	}
	if (len_raw == 0) { // guard
		LOG_ERROR("Unexpected error. %d bytes of RTSP Response", len_raw);
		goto erexit;
	}

#if AIRPLAY_DUMP_TRAFFIC
	hexdump("RTSP Response\n", buf_raw, len_raw);
#endif

if (rtspcld->cipher_enabled) {
		// NOTE: Must free(buf_plaintext) pre-decryption, because callback allocates the required memory
		LOG_DEBUG("free(buf_plaintext):%p", buf_plaintext);
		free(buf_plaintext);
		LOG_DEBUG("Decrypting. length %d into buf_plaintext(%p)", len_raw, buf_plaintext);
		rtspcld->ciphercb(rtspcld->ciphercb_arg, &buf_plaintext, &len_plaintext, buf_raw, len_raw, 0);
		LOG_DEBUG("buf_plaintext post decryption is %p", buf_plaintext);
		cipher_ratio = (float)len_raw/(float)len_plaintext;
		LOG_DEBUG("Cipher Ratio: %0.2f", cipher_ratio);
		if (cipher_ratio > CIPHER_RATIO) {
			LOG_ERROR("Actual Cipher Ratio (%0.2f) exceeds assumed (%0.2f)", cipher_ratio, CIPHER_RATIO);
			LOG_ERROR("Please raise a github issue at %s", GITHUB);
		}
	}
	else {
		LOG_DEBUG("Decryption not required. length %d", len_raw);
		memcpy(buf_plaintext, buf_raw, len_raw);
		len_plaintext = len_raw;
	}

	// We now have a complete RTSP Response message in buf_plaintext. This will consist of a Header and a Body.
	// The Body may be non-ascii. We should split buf_plaintext into two data buffers for each of the Header 
	// and the Body. This will make parsing the data much simpler and robust.
	temp_buf = malloc(len_plaintext+1); // need +1 in order to allow null termination
	if (!temp_buf) {
		LOG_ERROR("Unable to allocate memory for temporary buffer. %s", strerror(errno));
		goto erexit;
	}
	LOG_DEBUG("malloc(temp_buf):%d:%p", len_plaintext+1, temp_buf);
	memcpy(temp_buf, buf_plaintext, len_plaintext);
	// null terminate temp_buf, just to be safe for strstr call
	if (len_plaintext < RTSP_MAX_MESSAGE) {
		*(temp_buf+len_plaintext) = '\0';
	}
	else {
		LOG_ERROR("len_plaintext too big at %d", len_plaintext);
		goto erexit;
	}
	needle = strstr(temp_buf, "Content-Length: ");
	if (needle) {
		needle += strlen("Content-Length: ");
		token = strtok_r(needle, buf_plaintext_delimiters, &needle_ptr);
		clen = atoi(token);
		if (clen == 0) {
			response_body = NULL;
		}
		else {
			if ((response_body = malloc(clen)) == NULL ) {
				LOG_ERROR("Unable to malloc %d bytes for response_body. %s", clen, strerror(errno));
				goto erexit;
			}
			LOG_DEBUG("malloc(response_body):%d:%p", clen, response_body);
			memcpy(response_body, (buf_plaintext + len_plaintext - clen) , clen);
		}
	}
	else {
		clen = 0;
		response_body = NULL;
	}
	if ((response_header = malloc(len_plaintext - clen + 1)) == NULL) {
		LOG_ERROR("Unable to malloc %d bytes for response header", len_plaintext - clen);
		goto erexit;
	}
	LOG_DEBUG("malloc(response_header):%d, %p", len_plaintext - clen + 1, response_header);
	memcpy(response_header, buf_plaintext, len_plaintext - clen);
	*(response_header + len_plaintext - clen) = '\0'; // null terminate response header

	if (resp_content && resp_len) {
		*resp_len = clen;
		if (clen) {
			*resp_content = (char *)response_body;
		}
		else {
			*resp_content = NULL;
		}
	}

	line = strtok_r(response_header, buf_plaintext_delimiters, &header_ptr);
	token = strtok_r(line, delimiters, &line_ptr);
	if (!strncmp(token, "RTSP/1.0", strlen("RTSP/1.0"))) {
		rtspcld->rtsp_response = true;
	}
	else {
		rtspcld->rtsp_response = false;
		LOG_ERROR("Invalid RTSP/1.0 Response");
		goto erexit;
	}
	token = strtok_r(NULL, delimiters, &line_ptr);
	rtspcld->status_code = (int)strtol(token, NULL, 10);
	while ((token = strtok_r(NULL, delimiters, &line_ptr))) {
		if ((strlen(rtspcld->description) + 
			strlen(token) < sizeof(rtspcld->description))) {

			strcat(rtspcld->description, token);
			strcat(rtspcld->description, " ");
		}
	}

	i = 0;
	clen = 0;
	if (rkd) pkd = rkd;
	else pkd = lkd;
	pkd[0].key = NULL;

	while ((line = strtok_r(NULL, buf_plaintext_delimiters, &header_ptr))) {
		strncpy(resp_line, line, sizeof(resp_line));
		LOG_DEBUG("[%p]: <------ : %s", rtspcld, resp_line);

		if (i && resp_line[0] == ' ') {
			size_t j;
			for(j = 0; j < strlen(resp_line); j++) if (resp_line[j] != ' ') break;
			pkd[i].data = strdup(resp_line + j);
			continue;
		}

		dp = strstr(resp_line,":");

		if (!dp){
			LOG_ERROR("[%p]:Ignoring bad header data", rtspcld);
			// I think there may be an implementation bug in strtok_r. 
			// We sometimes get an extraneous character instead of
			// strtok_r returning NULL at the end. In which case, we will
			// continue instead of erexiting.
			continue;
		}

		*dp = 0;
		pkd[i].key = strdup(resp_line);
		pkd[i].data = strdup(dp + 1);

		i++;
		pkd[i].key = NULL;
	}
	
	pkd[i].key = NULL;
	if (!rkd) {
		LOG_DEBUG("kd_free(pkd):%p", pkd);
		kd_free(pkd);
	}

	if (buf_plaintext) {
		LOG_DEBUG("free(buf_plaintext):%p", buf_plaintext);
		free(buf_plaintext);
	}
	if (buf_raw) {
		LOG_DEBUG("free(buf_raw):%p", buf_raw);
		free(buf_raw);
	}
	if (temp_buf) {
		LOG_DEBUG("free(temp_buf):%p", temp_buf);
		free(temp_buf);
	}
	if (response_header) {
		LOG_DEBUG("free(response_header):%p", response_header);
		free(response_header);
	}
	// NOTE: The caller is responsible for freeing the response_body information
	return true;

erexit:
	LOG_ERROR("erexiting and freeing allocated memory buffers");
	if (buf_plaintext) free(buf_plaintext);
	if (buf_raw) free(buf_raw);
	if (pkd && pkd->key[0]) kd_free(pkd);
	if (temp_buf) free(temp_buf);
	if (response_header) free(response_header);
	if (response_body) free(response_body);
	return false;
}

// Process a RTSP Request and update caller with details of the RTSP Response
// @param p the RTSP client handle
// @param request the RTSP Request information
// @param response the RTSP Response data is returned to the caller via this parameter. Memory is allocated as required.
// @returns true on success, false on failure
// @note It is the responsibility of the caller to free the memory allocated for the response data
bool rtspcl_process_request(struct rtspcl_s *p, rtsp_request_t *request, rtsp_response_t *response) {
	char *resp_content = NULL;
	int resp_len = 0;
	// plist_t pinfo = NULL;
	key_data_t rkd[MAX_KD] = { 0 };

	if (!p) {
		LOG_ERROR("Invalid RTSP Client Handle");
		return false;
	}

	LOG_DEBUG("request->command: %s", request->command);
	LOG_DEBUG("request->content-type: %s", request->content_type);
	LOG_DEBUG("request->body.length: %d", request->body.length);
	if (*loglevel >- lDEBUG) hexdump("Body\n", (uint8_t *)request->body.mem, request->body.length);
	if (!exec_request_buf(p, request->command, request->content_type, request->body.mem, request->body.length,
		1, request->headers.kd, rkd, (char **) &resp_content, &resp_len, NULL)) {
		LOG_ERROR("exec request failed. Response length =%d", resp_len);
		goto erexit;
	}

	LOG_DEBUG("About to process header response");
	rtspcl_process_header_response(p, rkd, response);
	if (rkd->key[0]) kd_free(rkd);
	LOG_DEBUG("About to process body respose. Body length is %d. Address is %p", resp_len, resp_content);
	rtspcl_process_body_response(p, resp_content, resp_len, response);
	if (resp_content) {
		LOG_DEBUG("free(resp_content):%p", resp_content);
		free(resp_content);
	}

	return true;

erexit:
	if (rkd->key[0]) kd_free(rkd);
	return false;
}

// Extracts the RTSP response header information required for the AirPlay2 functions
// @note Extraction of the response body data is beyond the scope of this function
// @param p pointer to the RTSP client handle
// @param pkd the RTSP response header key data
// @param resp pointer to the RTSP response data to be stored
static void rtspcl_process_header_response(rtspcl_t *p, key_data_t *kd, rtsp_response_t *resp) {
	if (p == NULL) {
		LOG_ERROR("No RTSP client handle");
		return;
	}
	resp->rtsp_response = p->rtsp_response;
	resp->status_code = p->status_code;
	strncpy(resp->description, p->description, sizeof(resp->description));
	if ((kd == NULL) || !kd->key) {
		LOG_WARN("No key data in RTSP response header");
		return;
	}

	// work through the key data and extract the items relevant for AirPlay2 sequencing logic
	while (kd->key) {
		LOG_DEBUG("key: %s, data: %s", kd->key, kd->data);
		if (strncmp(kd->key, "Content-Type", strlen("Content-Type")) == 0)
			strncpy(resp->content_type, kd->data, sizeof(resp->content_type));
		(void)*kd++;
	}

	return;
}


// Extracts the RTSP response body information required for the AirPlay2 functions
// @note Extraction of the response header information is beyond the scope of this function
// @param p pointer to the RTSP client handle
// @param body the RTSP response body data
// @param len the length of the RTSP response body
// @param resp pointer to the RTSP response data to be stored
static void rtspcl_process_body_response(rtspcl_t *p, char *body, size_t len, rtsp_response_t *resp) {
	if (p == NULL) {
		LOG_ERROR("No RTSP client handle");
		return;
	}

	if (len == 0) {
		resp->length = len;
		return;
	}

	if (!(resp->content = malloc(len))) {
		LOG_ERROR("Unable to malloc memory for returning RTSP Response body. %s", strerror(errno));
		return;
	}
	LOG_DEBUG("malloc(resp->content):%d: %p", len, resp->content);
	memcpy(resp->content, body, len);
	resp->length = len;
	resp->alloced = true;

	return;
}

void rtspcl_set_ciphercb(struct rtspcl_s *p, 
	int (*cb)(void *, uint8_t **buf_out, size_t *buf_out_len, uint8_t *buf_in, int buf_in_len, int encrypt), 
	void *cbarg) {

		p->ciphercb = cb;
		p->ciphercb_arg = cbarg;
		p->cipher_enabled = true;
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
