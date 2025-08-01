/*
* RTSP related declarations that are shared betweenthe rtsp and airplay clients
*/

#ifndef __RTSP_COMMON_H
#define __RTSP_COMMON_H

// Added for AirPlay2 support
// This struct provides a means to expose RTSP response data to the airplay sequence handling logic
typedef struct rtsp_response_s {
	bool rtsp_response;		// True if we got a RTSP response. False otherwise
	int status_code;		// The RTSP status code of the response
	char description[256];	// The description of the status code
	char content_type[256];	// Make this an enum?
	int length;				// Length of the response content
	char **content;			// Memory must be freed by the consumer. Allocation only by AirPlay2 handlers
} rtsp_response_t;

#endif