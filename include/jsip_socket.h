#ifndef _JSIP_SOCKET_H_
#define _JSIP_SOCKET_H_
#include <sys/socket.h>
#include <vector>
#include <arpa/inet.h>
#include <iostream>
#include <functional>

#define MAX_PENDING_TCP 10
#define MAX_UDP_BUFF_LEN 1024
#define MAX_TCP_BUFF_LEN 1024

typedef struct sockaddr_in sockaddr_in_t;

typedef enum transport_ {
    TCP,
    UDP,
    SCTP
} transport_t;

class JSip_Socket {
    private:
        int tcp_sock_fd;
        int udp_sock_fd;
        uint16_t tcp_port;
        uint16_t udp_port;
        std::vector<sockaddr_in_t> service_addresses;
        std::function<void(char[MAX_UDP_BUFF_LEN] , char[INET_ADDRSTRLEN] , uint16_t , transport_t)> handler_callback;

    public:
        JSip_Socket();
        void start_server(std::function<void(char[MAX_UDP_BUFF_LEN] , char[INET_ADDRSTRLEN] , uint16_t , transport_t)> handler_callback);
        ~JSip_Socket() = default;
};
#endif