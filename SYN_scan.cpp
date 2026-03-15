#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>

using namespace std;

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short checksum(unsigned short *ptr,int nbytes)
{
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

int main()
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0){
        perror("socket");
        return 1;
    }

    char packet[4096];
    memset(packet, 0, 4096);

    struct iphdr *iph = (struct iphdr*) packet;
    struct tcphdr *tcph = (struct tcphdr*) (packet + sizeof(struct iphdr));

    sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);
    dest.sin_addr.s_addr = inet_addr("192.168.1.1");

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr("192.168.1.100");
    iph->daddr = dest.sin_addr.s_addr;

    iph->check = checksum((unsigned short*)packet, iph->tot_len);

    tcph->source = htons(12345);
    tcph->dest = htons(80);
    tcph->seq = htonl(0);
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);

    tcph->check = checksum((unsigned short*)tcph, sizeof(struct tcphdr));

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    if(sendto(sock, packet, iph->tot_len, 0,
              (sockaddr*)&dest, sizeof(dest)) < 0)
    {
        perror("sendto");
    }
    else
    {
        cout << "SYN packet sent\n";
    }

    close(sock);
}
