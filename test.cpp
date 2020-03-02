#include "include/jsip_socket.h"
#include "include/jsip_types.h"

void sip_handler(char message_buffer[MAX_UDP_BUFF_LEN] , char peer_address[INET_ADDRSTRLEN]  , uint16_t port , transport_t transport) 
{
    switch (transport)
    {
    case UDP:
        std::cout << "Message from " << peer_address << " on port udp:" << port << "\n";
        std::cout << message_buffer << "\n";
        break;
    case TCP:
        std::cout << "Message from " << peer_address << " on port tcp:" << port << "\n";
        std::cout << message_buffer << "\n";
        break;
    default:
        std::cout<<"unknown Transport\n";
        break;
    }
}

int main(){
    // auto server = Sip_Socket();
    // server.start_server(sip_handler);
    // auto sips_uri = jsip_uri(true , "voip.digicel.com","user","password",5060);
    // sips_uri.set_lr_param(true);
    // sips_uri.set_ttl_param(122);
    // sips_uri.set_param("tranport" , "tcp");
    // sips_uri.set_param("user" , "ip");
    // sips_uri.set_param("maddr" , "10.32.2.3");
    // sips_uri.set_param("method" , "invite");
    // sips_uri.set_param("jsip-ext-presence" , "active");
    // sips_uri.add_header("Subject","SIP testing");
    // sips_uri.set_param("method","INVITE");
    // sips_uri.add_header("Location","Meeting Room");
    // std::cout << sips_uri.to_string() << "\n";

    auto sip_uri =  jsip_uri(false , "voip.digicel.com","user","password",0);
    auto sip_uri2 = jsip_uri(false , "voip.digicel.com","user","password",5060);
    sip_uri2.set_param("new_param", "5");
    sip_uri2.set_param("security" , "off");
    
    auto sip_uri3 = jsip_uri(false , "voip.digicel.com","user","password",5060);
    sip_uri3.set_param("security" , "on");
    
    auto sip_uri4 = jsip_uri(false , "voip.digicel.com","","",5060);
    auto sip_uri5 = jsip_uri(false , "voip.digicel.com","jamal","",5060);

    auto parser1 = jsip_uri_parser("sips:user:password@voip.digicel.com:5060;new_param=5;security=off");
    auto parser2 = jsip_uri_parser(sip_uri4.to_string().c_str());
    auto parser3 = jsip_uri_parser(sip_uri5.to_string().c_str());
    auto parser4 = jsip_uri_parser("sip");
    auto parser5 = jsip_uri_parser("sips:user:password@voip.digicel.com;new_param=5;security=off");

    std::cout << "parsing 1: " << "sips:user:password@voip.digicel.com:5060;new_param=5;security=off\n";
    parser1.parse();
    std::cout << "parsing 2: " << sip_uri4.to_string() << "\n";
    parser2.parse();
    std::cout << "parsing 3: " << sip_uri5.to_string() << "\n";
    parser3.parse();
    std::cout << "parsing 4: " << "sips:user:password@voip.digicel.com;new_param=5;security=off\n";
    parser5.parse();
    return 0;
}