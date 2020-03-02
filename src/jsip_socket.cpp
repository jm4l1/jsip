#include "../include/jsip_socket.h"
#include <unistd.h>

JSip_Socket::JSip_Socket ()
{
    tcp_sock_fd = -1;
    udp_sock_fd = -1;
    tcp_port = 5060;
    udp_port = 5060;
};

void JSip_Socket::start_server(std::function<void(char[MAX_UDP_BUFF_LEN] , char[INET_ADDRSTRLEN] , uint16_t , transport_t)> handler_callback)
{
    sockaddr_in_t udp_address , tcp_address;
    //Listen on ports for each Protocol
    //create tcp socket
    tcp_sock_fd = socket(AF_INET , SOCK_STREAM , IPPROTO_IP);
    udp_sock_fd = socket(AF_INET , SOCK_DGRAM , IPPROTO_IP);
    if(tcp_sock_fd == -1 || udp_sock_fd == -1)
    {
        exit(EXIT_FAILURE);
    }
    udp_address.sin_family = AF_INET;
    udp_address.sin_addr.s_addr = INADDR_ANY;
    udp_address.sin_port = htons(udp_port);
    auto udp_bind = bind(udp_sock_fd, (struct sockaddr *)&udp_address, sizeof(udp_address));

    tcp_address.sin_family = AF_INET;
    tcp_address.sin_addr.s_addr = INADDR_ANY;
    tcp_address.sin_port = htons(tcp_port);
    auto tcp_bind = bind(tcp_sock_fd, (struct sockaddr *)&tcp_address, sizeof(sockaddr_in_t));

    if ((udp_bind < 0) || (tcp_bind < 0))
    {
        perror("failed to bind port");
        exit(EXIT_FAILURE);
    }
    sockaddr_in_t upd_peer_addr;
    memset(&upd_peer_addr , 0 , sizeof(sockaddr_in_t));
    char udp_recv_buff[MAX_UDP_BUFF_LEN];
    socklen_t len = sizeof(upd_peer_addr);
    if(listen(tcp_sock_fd , MAX_PENDING_TCP) < 0)
    {
        perror("failed to start on TCP port");
        exit(EXIT_FAILURE);
    }

    std::cout << "Listening on UDP/" << udp_port << "\n";
    std::cout << "Listening on TCP/" << tcp_port << "\n";

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(tcp_sock_fd , &read_set);
    FD_SET(udp_sock_fd , &read_set);

    while(1)
    {
        select(std::max(tcp_sock_fd , udp_sock_fd) + 1 , &read_set, nullptr , nullptr ,nullptr);
        if(FD_ISSET(udp_sock_fd , &read_set))
        {
            std::cout << "Incoming UDP connection \n";
            auto byte_len = recvfrom(udp_sock_fd , udp_recv_buff , MAX_UDP_BUFF_LEN , MSG_WAITALL , (sockaddr *)&upd_peer_addr  , &len );
            udp_recv_buff[byte_len] = '\0';
            len = sizeof(upd_peer_addr);
            auto peer_address = (sockaddr_in_t *)&upd_peer_addr; 
            handler_callback(udp_recv_buff,inet_ntoa(peer_address->sin_addr) , ntohs(peer_address->sin_port) , UDP);
        }
        if(FD_ISSET(tcp_sock_fd , &read_set))
        {
            std::cout << "Incoming TCP connection \n";
            int tcp_accept_fd = -1;
            char tcp_recv_buff[MAX_TCP_BUFF_LEN];
            int address_len = sizeof(tcp_address);
                tcp_accept_fd  = accept(tcp_sock_fd , (struct sockaddr *)&tcp_address , (socklen_t *) &address_len);
                if(tcp_accept_fd < 0)
                {
                    perror("Error Accepting connections");
                }
                auto pid = fork();
                if(pid == 0){
                    close(tcp_sock_fd);
                    tcp_sock_fd = -1;
                    auto byte_read = read(tcp_accept_fd , tcp_recv_buff , MAX_UDP_BUFF_LEN );
                    tcp_recv_buff[byte_read] = '\0';
                    if(getpeername(tcp_accept_fd , (sockaddr *) &tcp_address , (socklen_t *) &address_len) == 0)
                    {
                        auto peer_address = (sockaddr_in_t *)&tcp_address;
                        handler_callback(tcp_recv_buff,inet_ntoa(peer_address->sin_addr) , ntohs(peer_address->sin_port) , TCP);
                    }
                    close(tcp_accept_fd);
                    exit(EXIT_SUCCESS);
                }
                
        }
    }
};