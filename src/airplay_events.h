/*
 * Event handler for the AirPlay Events received from the AirPlay client device.
 * These are encrypted RTSP exchanges, encrypted with the cipher determined during pairing.
 * The AirPlay device generates the RTSP Request, and we respond with an appropriate RTSP Response
 * This event handler runs in its own thread.
 * 
 * Gratefully sourced from owntones, see https://github.com/ownetone/owntone-server
 */

#ifndef __AIRPLAY_EVENTS_H__
#define __AIRPLAY_EVENTS_H__

int
airplay_events_listen(const char *name, struct in_addr *address, unsigned short port, const uint8_t *key, size_t key_len);

int
airplay_events_init(void);

void
airplay_events_deinit(void);

#endif  /* !__AIRPLAY_EVENTS_H__ */
