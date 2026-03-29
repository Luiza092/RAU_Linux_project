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
#include <sstream> 
#include <fstream> 

using namespace std;

enum PortRangeType
{
    WELL_KNOWN, // 1-1023
    REGISTERED, // 1024-49151
    DYNAMIC, //49152-65535
    FULL //1-65535
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

class CidrParser
{
public:
    static bool is_cidr(const string& target)
    {
        return target.find('/') != string::npos;
    }

    static vector<string> expand(const string& cidr)
    {
        vector<string> result;

     
        // "192.168.1.0/24" → ip_str="192.168.1.0", prefix=24
        size_t slash = cidr.find('/');
        string ip_str = cidr.substr(0, slash);
        int prefix    = stoi(cidr.substr(slash + 1));

        uint32_t base_ip;
        inet_pton(AF_INET, ip_str.c_str(), &base_ip);
        base_ip = ntohl(base_ip); // ~host byte order

        uint32_t mask       = prefix == 0 ? 0 : (~0u << (32 - prefix));
        uint32_t host_count = ~mask;

        for(uint32_t i = 0; i <= host_count; i++)
        {
            uint32_t current = htonl(base_ip + i);
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &current, buf, sizeof(buf));
            result.push_back(string(buf));
        }

        return result;
    }
};

class ArgumentParser
{
public:
    string target_ip;
    int start_port = 1;
    int end_port = 65535;
    vector<int> specific_ports;
    int timeout_sec = 2;
    int retries = 1;

    bool parse(int argc, char* argv[])
    {
        int opt;

        while((opt = getopt(argc, argv, "t:s:e:p:T:r:")) != -1)
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

		case 'p':
		{
    		    string ports_str = optarg; // "80,443"
    		    stringstream ss(ports_str);
    		    string token;
    		    while(getline(ss, token, ','))
        	      specific_ports.push_back(stoi(token));
    		    break;
		}
		case 'T':
		{
    		    timeout_sec = atoi(optarg);
    		    break;
		}

		case 'r':
		{
    		    retries = atoi(optarg);
    		    break;
		}

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
        cout << "sudo ./scanner -t <ip or CIDR>\n";
	cout << "-s <start_port> -e <end_port>\n";
	cout << "-p <port1, port2, ...>\n";
	cout << "-T <timeout_sec>\n";
	cout << "-r <retries>\n";
    }
};

class JsonExporter
{
public:
    void add(const string& ip, int port, const string& status)
    {
        entries.push_back({ip, port, status});
    }

    void save(const string& filename)
    {
        ofstream file(filename);
        file << "[\n";

        for(size_t i = 0; i < entries.size(); i++)
        {
            auto& e = entries[i];
            file << "  { \"ip\": \""  << e.ip
                 << "\", \"port\": "  << e.port
                 << ", \"status\": \"" << e.status << "\" }";

            if(i + 1 < entries.size()) file << ",";
            file << "\n";
        }

        file << "]\n";
        cout << "Результаты сохранены в " << filename << "\n";
    }

private:
    struct Entry { string ip; int port; string status; };
    vector<Entry> entries;
};

class SynScanner
{
private:
    string target_ip;
    int timeout_sec;
    int retry_count;
    JsonExporter& exporter;
public:
    SynScanner(const string& ip, int timeout, int retries, JsonExporter& exp)
    : target_ip(ip), timeout_sec(timeout), retry_count(retries),exporter(exp) {}

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

	iph->saddr = inet_addr("10.0.2.15");
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
        timeout.tv_sec = timeout_sec; 
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, sizeof(timeout));

        char buffer[4096];

	for(int attempt = 0; attempt < retry_count; attempt++)
    	{
       	    if(recv(sock, buffer, sizeof(buffer), 0) > 0)
            {
                iphdr*  recv_ip  = (iphdr*)buffer;
                tcphdr* recv_tcp = (tcphdr*)(buffer + recv_ip->ihl * 4);
 
                if(recv_tcp->syn && recv_tcp->ack)
                {
                    cout << "Port " << port << " OPEN\n";
                    exporter.add(target_ip, port, "OPEN"); // НОВОЕ
                    return;
                }
                else if(recv_tcp->rst)
                {
                    cout << "Port " << port << " CLOSED\n";
                    exporter.add(target_ip, port, "CLOSED"); // НОВОЕ
                    return;
                } 
	    }
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

    JsonExporter exporter;

    vector<string> targets; //IP addresses
    if(CidrParser::is_cidr(parser.target_ip))
	targets = CidrParser::expand(parser.target_ip);
    else
	targets.push_back(parser.target_ip);

    int start = 1;
    int end = 65535;//ports
    if(parser.specific_ports.empty())
    {       
        get_range(FULL, start, end);
        if(parser.start_port != 1)
	    start = parser.start_port;
	if(parser.end_port != 65535) 
	    end = parser.end_port;
    }

    for(const string& ip : targets)
    {
	cout << "\nScan: " << ip << "\n";

        SynScanner scanner(ip, parser.timeout_sec, parser.retries, exporter);

	if(!parser.specific_ports.empty())
	{
	    for(int port : parser.specific_ports) //specport
		 scanner.scan_port(port);
	}
	else
	{
	    run_threads(scanner, start, end, 10);
	}
    }

    exporter.save("results.json");

    return 0;
}
