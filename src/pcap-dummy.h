#pragma once

typedef struct pcap pcap_t;

pcap_t *pcap_open_dummy(int linktype, int snaplen);

/** Get pcap->errbuf without importing pcap-int. */
const char *_pcap_errbuf(pcap_t *pcap);
