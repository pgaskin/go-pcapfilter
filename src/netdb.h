#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define EAI_NONAME   -2
#define EAI_SERVICE  -8
#define EAI_SYSTEM   -11
#define EAI_AGAIN    -3
#define EAI_FAIL     -4
#define EAI_FAMILY   -6
#define EAI_MEMORY   -10
#define EAI_NODATA   -5
#define EAI_SOCKTYPE -7

#define AI_PASSIVE     0x01
#define AI_CANONNAME   0x02
#define AI_NUMERICHOST 0x04
#define AI_NUMERICSERV 0x08

struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};

struct hostent {
    char  *h_name;
    char **h_aliases;
    int    h_addrtype;
    int    h_length;
    char **h_addr_list;
};
#define h_addr h_addr_list[0]

struct netent {
    char     *n_name;
    char    **n_aliases;
    int       n_addrtype;
    uint32_t  n_net;
};

struct protoent {
    char  *p_name;
    char **p_aliases;
    int    p_proto;
};

struct servent {
    char  *s_name;
    char **s_aliases;
    int    s_port;
    char  *s_proto;
};

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);
const char *gai_strerror(int errcode);
struct hostent *gethostbyname(const char *name);
struct netent *getnetbyname(const char *name);
struct protoent *getprotobyname(const char *name);
struct servent *getservbyname(const char *name, const char *proto);
