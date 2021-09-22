#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        	struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
	        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + 14);
	        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet + 14 + 20);
	        u_char* payload = (u_char*)(packet + 14 + 20 + 20);

	        printf("%u bytes captured\n\n", header->caplen);

	        printf("Ethernet Header\n");
	        printf("src mac\t%02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[5], eth->ether_shost[4], eth->ether_shost[3], eth->ether_shost[2], eth->ether_shost[1], eth->ether_shost[0]);
	        printf("dst mac\t%02x:%02x:%02x:%02x:%02x:%02x\n\n", eth->ether_dhost[5], eth->ether_dhost[4], eth->ether_dhost[3], eth->ether_dhost[2], eth->ether_dhost[1], eth->ether_dhost[0]);

        	printf("IP Header\n");
	        printf("src ip\t%s\n", inet_ntoa(ip->ip_src));
	        printf("dst ip\t%s\n\n", inet_ntoa(ip->ip_dst));

	        printf("TCP Header\n");
	        printf("src port\t%d\n", ntohs(tcp->th_sport));
	        printf("dst port\t%d\n\n", ntohs(tcp->th_dport));

	        printf("Payload hexadecimal value\n");
	        u_int payload_size = header->caplen - 14 - 20 - 20;
		if(payload_size <= 8) {
        	    for(int i = 0; i < payload_size; i++) {
                	printf("%02x ", *(payload + i));
	            }
	        }
	        else {
	            for(int i = 0; i < 8; i++) {
	                printf("%02x ", *(payload + i));
	            }
	        }

	        printf("\n\n-----------------------\n\n");

	}

	pcap_close(pcap);
}
