#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <pcap/pcap.h>

#define PCAP_BUF	12655

int httpArr[PCAP_BUF];
int httpIdx = 0;
char httpIP[PCAP_BUF][INET_ADDRSTRLEN];
long httpDataLen = 0;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    int maxHttpLen = 0, maxHttpIdx = 0;
    pcap_t *fp;

    if (argc != 2) {
        fprintf(stderr, "\npacket file path must be specified\n");
        exit(EXIT_FAILURE);
    }

    if (!(fp = pcap_open_offline(argv[1], errbuf))) {
	    fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        exit(EXIT_FAILURE);
    } 

    for (int i = 0; i < httpIdx; i++) {
        if (maxHttpLen < httpArr[i]) {
            maxHttpLen = httpArr[i];
            maxHttpIdx = i;
        }
    }

    printf("HTTP traffic flows: %d\n",  httpIdx);
    printf("HTTP traffic bytes: %ld\n",httpDataLen);
    printf("Top HTTP hostname : %s\n",  httpIP[maxHttpIdx]);
    
    exit(EXIT_SUCCESS);
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    struct ether_header* ethernetHeader;
    struct ip* ipHeader;
    struct tcphdr* tcpHeader;
    char destIP[INET_ADDRSTRLEN];
    int dataLength = 0;
    u_int sourcePort, destPort;

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
    {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip)+ 4 + sizeof(struct tcphdr));
    }
    else {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header) + 4); // + 4 for vlan header
        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + 4 + sizeof(struct ip)); // + 4 for vlan header
        dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + 4 + sizeof(struct tcphdr)); // + 4 for vlan header
    }

    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

    sourcePort = ntohs(tcpHeader->source);
    destPort = ntohs(tcpHeader->dest);
    
    if (sourcePort == 80 || sourcePort == 443 || destPort == 80 || destPort == 443) {
        for (int i = 0; i < httpIdx; i++) {
            if (strcmp(destIP, httpIP[i]) == 0) {
                httpArr[i] = httpArr[i] + dataLength;
            }
        }
        strcpy(httpIP[httpIdx], destIP);
        httpArr[httpIdx] = dataLength;
        httpIdx = httpIdx + 1;
        httpDataLen += dataLength;
    }
}