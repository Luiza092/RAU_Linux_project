#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <thread>
#include <vector>

using namespace std;

enum PortRangeType
{
    WELL_KNOWN,
    REGISTERED,
    DYNAMIC,
    FULL
};

void get_range(PortRangeType type, int& start, int& end)
{
    switch(type)
    {
        case WELL_KNOWN:
            start = 1;
            end = 1023;
            break;

        case REGISTERED:
            start = 1024;
            end = 49151;
            break;

        case DYNAMIC:
            start = 49152;
            end = 65535;
            break;

        case FULL:
        default:
            start = 1;
            end = 65535;
            break;
    }
}

class Checksum
{
public:
    static unsigned short calculate(unsigned short* data, int length)
    {
        long sum = 0;
        unsigned short oddbyte;
        unsigned short answer;

        while(length > 1)
        {
            sum += *data++;
            length -= 2;
        }

        if(length == 1)
        {
            oddbyte = 0;
            *((u_char*)&oddbyte) = *(u_char*)data;
            sum += oddbyte;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);

        answer = (short)~sum;
        return answer;
    }
};

struct PseudoHeader
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

class ArgumentParser
{
public:
    string target_ip;
    int start_port = 1;
    int end_port = 65535;

    bool parse(int argc, char* argv[])
    {
        int opt;

        while((opt = getopt(argc, argv, "t:s:e:")) != -1)
        {
            switch(opt)
            {
                case 't':
                    target_ip = optarg;
                    break;

                case 's':
                    start_port = atoi(optarg);
                    break;

                case 'e':
                    end_port = atoi(optarg);
                    break;

                default:
                    print_help();
                    return false;
            }
        }

        if(target_ip.empty())
        {
            print_help();
            return false;
        }

        return true;
    }

private:
    void print_help()
    {
        cout << "Usage:\n";
        cout << "sudo ./scanner -t <target_ip> -s <start_port> -e <end_port>\n";
    }
};

class SynScanner
{
private:
    string target_ip;
public:
    SynScanner(const string& ip) : target_ip(ip) {}

    void scan_port(int port)
    {
        int sock = create_socket();
        if(sock < 0)
            return;

        char packet[4096];
        memset(packet, 0, sizeof(packet));

        iphdr* iph = (iphdr*)packet;
        tcphdr* tcph = (tcphdr*)(packet + sizeof(iphdr));

        sockaddr_in dest = create_dest(port);

        build_ip_header(iph, dest);
        build_tcp_header(tcph, port);

        calculate_tcp_checksum(iph, tcph);

        send_packet(sock, packet, ntohs(iph->tot_len), dest);

        receive_response(sock, port);

        close(sock);
    }

private:
    int create_socket()
    {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

        if(sock < 0)
        {
            perror("socket");
            return -1;
        }

        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        return sock;
    }

    sockaddr_in create_dest(int port)
    {
        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);

        inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

        return dest;
    }

    void build_ip_header(iphdr* iph, const sockaddr_in& dest)
    {
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr));
        iph->id = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;

        iph->saddr = inet_addr("127.0.0.1");
        iph->daddr = dest.sin_addr.s_addr;

        iph->check = Checksum::calculate((unsigned short*)iph,
            sizeof(iphdr));
    }

    void build_tcp_header(tcphdr* tcph, int port)
    {
        tcph->source = htons(rand() % 65535);
        tcph->dest = htons(port);
        tcph->seq = htonl(rand());
        tcph->ack_seq = 0;

        tcph->doff = 5;
        tcph->syn = 1;

        tcph->window = htons(65535);
        tcph->check = 0;
    }

    void calculate_tcp_checksum(iphdr* iph, tcphdr* tcph)
    {
        PseudoHeader pseudo{};

        pseudo.source_address = iph->saddr;
        pseudo.dest_address = iph->daddr;
        pseudo.placeholder = 0;
        pseudo.protocol = IPPROTO_TCP;
        pseudo.tcp_length = htons(sizeof(tcphdr));

        char pseudo_packet[65535];

        memcpy(pseudo_packet, &pseudo, sizeof(pseudo));
        memcpy(pseudo_packet + sizeof(pseudo), tcph, sizeof(tcphdr));

        tcph->check = Checksum::calculate((unsigned short*)pseudo_packet,
            sizeof(pseudo) + sizeof(tcphdr));
    }

    void send_packet(int sock, char* packet, int length, sockaddr_in& dest)
    {
        if(sendto(sock, packet, length, 0, (sockaddr*)&dest,
            sizeof(dest)) < 0)
        {
            perror("sendto");
        }
    }

    void receive_response(int sock, int port)
    {
        timeval timeout{};
        timeout.tv_sec = 2;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, sizeof(timeout));

        char buffer[4096];

        if(recv(sock, buffer, sizeof(buffer), 0) > 0)
        {
            iphdr* recv_ip = (iphdr*)buffer;

            tcphdr* recv_tcp = (tcphdr*)(buffer + recv_ip->ihl * 4);
            if(recv_tcp->syn && recv_tcp->ack)
                cout << "Port " << port << " OPEN\n";
            else if(recv_tcp->rst)
                cout << "Port " << port << " CLOSED\n";
        }
    }
};

void scan_worker(SynScanner& scanner, int start, int end)
{
    for(int port = start; port <= end; ++port)
    {
        scanner.scan_port(port);
    }
}

void run_threads(SynScanner& scanner, int start, int end, int thread_count)
{
    std::vector<std::thread> threads;

    int total_ports = end - start + 1;
    int chunk = total_ports / thread_count;

    int current_start = start;

    for(int i = 0; i < thread_count; i++)
    {
        int current_end = (i == thread_count - 1)
            ? end
            : current_start + chunk - 1;

        threads.emplace_back(scan_worker,
            std::ref(scanner),
            current_start,
            current_end);

        current_start = current_end + 1;
    }

    for(auto& t : threads)
        t.join();
}

int main(int argc, char* argv[])
{
    ArgumentParser parser;

    if(!parser.parse(argc, argv))
        return 1;

    int start, end;

    get_range(FULL, start, end);

    SynScanner scanner(parser.target_ip);

    int thread_count = 10;

    run_threads(scanner, start, end, thread_count);

    return 0;
}
