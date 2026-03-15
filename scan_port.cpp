  #include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int scan_port(const char* ip, int port) {
 int sock = socket(AF_INET, SOCK_STREAM, 0);
 if(sock < 0) {
  perror("socket");
  return -1;
 }

 sockaddr_in target{};
 target.sin_family = AF_INET;
 target.sin_port = htons(port);

 if(inet_pton(AF_INET, ip, &target.sin_addr) <= 0) {
  std::cerr << "Invalid IP address\n";
  close(sock);
  return -1;
 }

 int result = connect(sock, (sockaddr*)&target, sizeof(target));

 if(result == 0){
  std::cout << "Port " <<port << " is Open\n";
 }else{
  if (errno == ECONNREFUSED)
   std::cout << "Port " << port << " is CLOSED\n";
  else
   std::cout << "Port " << port << " is FILTERED or ERROR\n";
 }

 close(sock);
 return 0;
}

int main() {
    const char* target_ip = "127.0.0.1";

    for (int port = 9080; port <= 9100; ++port) {
        scan_port(target_ip, port);
    }
    return 0;
}
