
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdbool.h>

#include "cross_log.h"

// union net_sockaddr
// {
//   struct sockaddr_in sin;
//   struct sockaddr_in6 sin6;
//   struct sockaddr sa;
//   struct sockaddr_storage ss;
// };

extern log_level 	main_log;
static log_level 	*loglevel = &main_log;

int net_connect(const char *addr, unsigned short port, int type, bool set_nonblock)
{
  struct addrinfo hints = { 0 };
  struct addrinfo *servinfo;
  struct addrinfo *ptr;
  char strport[8];
  int flags;
  int fd;
  int ret;

  LOG_DEBUG("Connecting to %s (port %u)\n", addr, port);

  hints.ai_socktype = type;
  hints.ai_family = AF_INET;

  snprintf(strport, sizeof(strport), "%hu", port);
  ret = getaddrinfo(addr, strport, &hints, &servinfo);
  if (ret < 0)
    {
      LOG_ERROR("Could not get address info for %s (port %u): %s\n", addr, port, gai_strerror(ret));
      return -1;
    }

  for (ptr = servinfo; ptr; ptr = ptr->ai_next)
    {
      fd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
      if (fd < 0)
	{
	  continue;
	}

      // For Linux we could just give SOCK_CLOEXEC to socket(), but that won't
      // work with MacOS, so we have to use fcntl()
      flags = fcntl(fd, F_GETFL, 0);
      if (flags < 0)
	continue;
      if (set_nonblock)
	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK | O_CLOEXEC);
      else
	ret = fcntl(fd, F_SETFL, flags | O_CLOEXEC);
      if (ret < 0)
	continue;

      ret = connect(fd, ptr->ai_addr, ptr->ai_addrlen);
      if (ret < 0 && errno != EINPROGRESS) // EINPROGRESS in case of nonblock
	{
	  close(fd);
	  continue;
	}

      break;
    }

  freeaddrinfo(servinfo);

  if (!ptr)
    {
      LOG_ERROR("Could not connect to %s (port %u): %s\n", addr, port, strerror(errno));
      return -1;
    }

  // net_address_get(ipaddr, sizeof(ipaddr), (union net_sockaddr *)ptr->ai-addr);

  return fd;
}