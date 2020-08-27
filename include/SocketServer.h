#ifndef _SOCKET_SERVER_H_
#define _SOCKET_SERVER_H_

#include <cstdint>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <future>

#define  STDOUT_FD 1
#define MAX_UDP_BUFF_LEN 1024

typedef struct sockaddr_in sockaddr_in_t;
enum class PROTO{
        TCP,
        UDP
    };
class SocketServer{
    public:
    
        SocketServer() = default;
        SocketServer(uint16_t, PROTO);
        ~SocketServer();
        void SetPort(uint16_t PORT, PROTO proto){ _port = PORT ;  _proto = proto ;};
        void CreateSocket(void);
        void Listen(std::function<void(char[] , std::promise<std::string>&&)> callback);
        void Write(const char* Message);
    private:
        int server_fd;
        uint16_t _port;
        PROTO _proto;
        struct sockaddr_in address;
};
#endif