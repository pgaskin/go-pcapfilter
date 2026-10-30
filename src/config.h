#pragma once

#define LIBPCAP_CONFIG_H

#define HAVE_SNPRINTF 1
#define HAVE_VSNPRINTF 1
#define HAVE_ASPRINTF 1
#define HAVE_VASPRINTF 1
#define HAVE_STRLCPY 1
#define HAVE_STRLCAT 1
#define HAVE_STRTOK_R 1
#define HAVE_UNISTD_H 1

#define HAVE_BUILTIN_BSWAP16 1
#define HAVE_BUILTIN_BSWAP32 1
#define HAVE_BUILTIN_BSWAP64 1
#define HAVE_BUILTIN_CTZ 1

#define SIZEOF_TIME_T 8
#define SIZEOF_VOID_P 4

#define HAVE_ETHER_HOSTTON 1

#define PACKAGE_NAME "libpcap"
#define PACKAGE_VERSION "unknown"
#define PACKAGE_STRING "libpcap (wasm)"
