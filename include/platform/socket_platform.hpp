#ifndef SOCKET_PLATFORM_H 
#define SOCKET_PLATFORM_H

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#endif