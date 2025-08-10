#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include "player.h"
#include "cross_log.h"

extern log_level 	main_log;
static log_level 	*loglevel = &main_log;

void player_playback_pause(void) {
    LOG_DEBUG("player_playback_pause() called from reverse RTSP connection");
}

void player_playback_start(void) {
    LOG_DEBUG("player_playback_start() called from reverse RTSP connection");
}

void player_playback_next(void) {
    LOG_DEBUG("player_playback_next() called from reverse RTSP connection");
}

void player_playback_prev(void) {
    LOG_DEBUG("player_playback_prev() called from reverse RTSP connection");
}

void player_get_status(struct player_status *status) {
    LOG_DEBUG("player_get_status() called from reverse RTSP connection");
    status->status = PLAY_STOPPED;
    status->repeat = REPEAT_OFF;
    status->shuffle = '\0';
    status->consume = '\0';
    status->volume = 0;
}