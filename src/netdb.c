#include <netdb.h>
#include <stdlib.h>

#include "bpf.h"

int getaddrinfo(const char *node, __attribute__((unused)) const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    if (node == NULL) {
        return EAI_NONAME;
    }

    int family = hints ? hints->ai_family : AF_UNSPEC;
    int socktype = hints ? hints->ai_socktype : 0;

    *res = NULL;
    struct addrinfo **tail = res;

    if (family == AF_UNSPEC || family == AF_INET) {
        struct in_addr addr4;
        if (_env_resolve_host(node, 4, &addr4) == 0) {
            struct addrinfo *ai = calloc(1, sizeof(*ai));
            struct sockaddr_in *sin = calloc(1, sizeof(*sin));
            if (ai && sin) {
                sin->sin_family = AF_INET;
                sin->sin_addr = addr4;
                ai->ai_family = AF_INET;
                ai->ai_socktype = socktype;
                ai->ai_addrlen = sizeof(*sin);
                ai->ai_addr = (struct sockaddr *)sin;
                *tail = ai; tail = &ai->ai_next;
            } else {
                free(ai);
                free(sin);
            }
        }
    }

    if (family == AF_UNSPEC || family == AF_INET6) {
        struct in6_addr addr6;
        if (_env_resolve_host(node, 6, &addr6) == 0) {
            struct addrinfo *ai = calloc(1, sizeof(*ai));
            struct sockaddr_in6 *sin6 = calloc(1, sizeof(*sin6));
            if (ai && sin6) {
                sin6->sin6_family = AF_INET6;
                sin6->sin6_addr = addr6;
                ai->ai_family = AF_INET6;
                ai->ai_socktype = socktype;
                ai->ai_addrlen = sizeof(*sin6);
                ai->ai_addr = (struct sockaddr *)sin6;
                *tail = ai; tail = &ai->ai_next;
            } else {
                free(ai);
                free(sin6);
            }
        }
    }

    return *res == NULL ? EAI_NONAME : 0;
}

void freeaddrinfo(struct addrinfo *res) {
    while (res) {
        struct addrinfo *next = res->ai_next;
        free(res->ai_addr);
        free(res);
        res = next;
    }
}

const char *gai_strerror(__attribute__((unused)) int errcode) {
    return "error"; // stub
}

struct hostent *gethostbyname(const char *name) {
    static uint32_t s_h_addr;
    static char *s_addr_list[2] = {
        (char *)&s_h_addr,
        NULL,
    };
    static struct hostent s_hostent = {
        .h_addrtype = AF_INET,
        .h_length = 4,
        .h_addr_list = s_addr_list,
    };
    if (_env_resolve_host(name, 4, &s_h_addr) != 0) {
        return NULL;
    }
    s_hostent.h_name = (char *)name;
    return &s_hostent;
}

struct netent *getnetbyname(__attribute__((unused)) const char *name) {
    return NULL; // stub
}

struct protoent *getprotobyname(__attribute__((unused)) const char *name) {
    return NULL; // stub
}

struct servent *getservbyname(__attribute__((unused)) const char *name, __attribute__((unused)) const char *proto) {
    return NULL; // stub
}
