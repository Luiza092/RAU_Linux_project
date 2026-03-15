  #include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int port = 9090;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    // Позволяет быстро перезапускать сервер
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  // слушать все интерфейсы
    address.sin_port = htons(port);

    if (bind(server_fd, (sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    std::cout << "Server listening on port " << port << "...\n";

    while (true) {
        sockaddr_in client{};
        socklen_t client_len = sizeof(client);

        int client_fd = accept(server_fd, (sockaddr*)&client, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        std::cout << "Client connected\n";

        const char* banner = "Test server: port is OPEN\n";
        send(client_fd, banner, strlen(banner), 0);

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
