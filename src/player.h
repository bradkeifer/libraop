#ifndef __H_PLAYER_
#define __H_PLAYER_

/*---------- Copied from player.[c,h] to provide wrapper -----------------------------*/
// See also the enum defined in cliraop.c and see if we can/should harmonise and/or integrate
enum play_status {
  PLAY_STOPPED = 2,
  PLAY_PAUSED  = 3,
  PLAY_PLAYING = 4,
};

enum repeat_mode {
  REPEAT_OFF  = 0,
  REPEAT_SONG = 1,
  REPEAT_ALL  = 2,
};

struct player_status {
  enum play_status status;
  enum repeat_mode repeat;
  char shuffle;
  char consume;

  int volume;

  /* Playlist id */
  uint32_t plid;
  /* Id of the playing file/item in the files database */
  uint32_t id;
  /* Item-Id of the playing file/item in the queue */
  uint32_t item_id;
  /* Elapsed time in ms of playing item */
  uint32_t pos_ms;
  /* Length in ms of playing item */
  uint32_t len_ms;
};

/*----------------------------------------*/

void player_playback_pause(void);
void player_playback_start(void);
void player_playback_next(void);
void player_playback_prev(void);
void player_get_status(struct player_status *status);

#endif