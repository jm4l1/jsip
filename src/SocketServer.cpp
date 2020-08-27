#include "SocketServer.h"
#include <sstream>
#include <iostream>
#include <thread>
#include <cstring>

SocketServer::SocketServer(uint16_t port , PROTO proto):_port(port),_proto(proto){
    CreateSocket();
}
SocketServer::~SocketServer(){
    std::cout << "Terminating Server.\n";
    close(server_fd);
}
void SocketServer::CreateSocket(){
    std::cout << "[CreateSocket] - Starting SocketServer \n";

    server_fd =  _proto == PROTO::TCP ?  socket(AF_INET, SOCK_STREAM, IPPROTO_IP) : socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) ; 

    if (server_fd == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "[CreateSocket] - Socket Created Successfully with FD:  " << server_fd << "\n"; 
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(_port);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    std::cout << "[CreateSocket] - Socket bound to port " << _port << "\n";
}
void SocketServer::Listen(std::function<void(char[] , std::promise<std::string>&& )> connection_callback){
    int connect_socket;
    int addrlen = sizeof(address);
    struct sockaddr address;
    
    std::cout << "[SocketServer] - Listening on * " << _port << "\n";

    if(_proto == PROTO::TCP )
    {
        if (listen(server_fd, 3) < 0)
        {
            perror("listen");
            exit(EXIT_FAILURE);
        }
    }
    while(1){  
       
        //with threading
        //handle on child thread
        if(_proto == PROTO::TCP){ 
            if ((connect_socket = accept(server_fd, (struct sockaddr *)&address, 
                                 (socklen_t*)&addrlen))<0){
                perror("accept");
                exit(EXIT_FAILURE);
            }
            std::cout << "Incoming connection on TCP socket\n";
            auto thread_handler = [&](int &&connect_socket){
                socklen_t len = sizeof(address);
                uint16_t port;
                struct sockaddr_in* addressInternet;
                int valread;
                char buffer[1024] = {0};
                std::promise<std::string> response_prms;
                std::future<std::string> ftr = response_prms.get_future();
                if(getpeername(connect_socket, &address,&len) == 0){
                    addressInternet = (struct sockaddr_in*) &address;
                    port = ntohs ( addressInternet->sin_port );    
                    // std::cout << "Connection received from on child thread " << inet_ntoa( addressInternet->sin_addr) << " on port " << port << "\n";
                }
                valread = read( connect_socket , buffer, 1024);
                connection_callback(buffer,std::move(response_prms));
                auto response = ftr.get();
                write(connect_socket,response.c_str(),response.size());
                shutdown(connect_socket,SHUT_WR);
                close(connect_socket);
            };
            std::thread t(thread_handler,std::move(connect_socket));
            t.detach();
        }
        if(_proto == PROTO::UDP){
            char udp_recv_buff[MAX_UDP_BUFF_LEN];
            sockaddr_in_t upd_peer_addr;
            socklen_t len = sizeof(upd_peer_addr);
            memset(&upd_peer_addr , 0 , sizeof(sockaddr_in_t));
            auto byte_len = recvfrom(server_fd , udp_recv_buff , MAX_UDP_BUFF_LEN , MSG_WAITALL , (sockaddr *)&upd_peer_addr  , &len );
            auto udp_handler = [&](){
                memset(&upd_peer_addr , 0 , sizeof(sockaddr_in_t));
                std::cout << "Incoming connection on UDP socket\n";
                std::promise<std::string> response_prms;
                std::future<std::string> ftr = response_prms.get_future();
                sockaddr_in_t upd_peer_addr;
                udp_recv_buff[byte_len] = '\0';
                len = sizeof(upd_peer_addr);
                auto peer_address = (sockaddr_in_t *)&upd_peer_addr; 
                connection_callback(udp_recv_buff,std::move(response_prms));
                ftr.get();
            };
            std::thread t(udp_handler);
            t.detach();
        }
    }    
}
void SocketServer::Write(const char * Message){;
        write(server_fd,Message,strlen(Message));
}