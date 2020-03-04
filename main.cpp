#include "include/jsip_socket.h"
#include "include/jsip_types.h"
#include <cstdlib>

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
    std::srand(std::time(0));
    // auto server = JSip_Socket();
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

    // auto sip_uri =  jsip_uri(false , "voip.digicel.com","user","password",0);
    // auto sip_uri2 = jsip_uri(false , "voip.digicel.com","user","password",5060);
    // sip_uri2.set_param("new_param", "5");
    // sip_uri2.set_param("security" , "off");
    
    // auto sip_uri3 = jsip_uri(false , "voip.digicel.com","user","password",5060);
    // sip_uri3.set_param("security" , "on");
    
    // auto sip_uri4 = jsip_uri(false , "voip.digicel.com","","",5060);
    // auto sip_uri5 = jsip_uri(false , "voip.digicel.com","jamal","",0);
    // sip_uri5.add_header("Subject","SIP testing");
    // sip_uri5.add_header("Location","testing room");
    // sip_uri5.set_lr_param(true);

    // auto parser1 = jsip_uri_parser("sips:user:password@voip.digicel.com:5060;new_param=5;security=off?Subject=\"SIP testing\"");
    // auto parser2 = jsip_uri_parser(sip_uri4.to_string().c_str());
    // auto parser3 = jsip_uri_parser(sip_uri5.to_string().c_str());
    // auto parser4 = jsip_uri_parser("sip");
    // auto parser5 = jsip_uri_parser("sips:user:password@voip.digicel.com;new_param=5;security=off");

    // std::cout << "parsing 1: " << "sips:user:password@voip.digicel.com:5060;new_param=5;security=off?Subject=\"SIP testing\"\n";
    // parser1.parse();
    // std::cout << "parsed as " << parser1.get_uri().to_string() << "\n"; 
    // std::cout << "parsing 2: " << sip_uri4.to_string() << "\n";
    // parser2.parse();
    // std::cout << "parsing 3: " << sip_uri5.to_string() << "\n";
    // parser3.parse();
    // std::cout << "parsing 4: " << "sips:user:password@voip.digicel.com;new_param=5;security=off\n";
    // parser5.parse();

    // std::cout << convert_to_escaped_string("246?:@5&3@00009",URI_USER_RESERVED_SET) << '\n';
    // randomize_cseq();
    // for(int i = 0 ; i < 20 ; ++i)
    // {
    //     std::cout << "current is " << get_next_cseq() << "\n";
    // }
    // return 0;
    randomize_cseq();
    auto request_uri = jsip_uri(false , "voip.digicel.com" , "" , "" , 5060);
    auto request = jsip_request(jsip_method_t::INVITE  , request_uri , globallyUniqueId("JSIP-" , 80) , "user@target.com","" , "user@local.com" , "",jsip_method_t::INVITE , get_next_cseq() , 70 );
    jsip_via via1;
    jsip_via via2;
    jsip_via via3;
    via1.set_sent_host("server10.biloxi.com");
    via1.set_transport("UDP");
    via1.set_branch("z9hG4bKnashds8");
    via1.set_received("192.0.2.3");
    via2.set_sent_host("bigbox3.site3.atlanta.com");
    via2.set_transport("UDP");
    via2.set_branch("z9hG4bK77ef4c2312983.1");
    via2.set_received("192.0.2.2");
    via2.set_ttl(128);
    via3.set_sent_host("pc33.atlanta.com");
    via3.set_transport("UDP");
    via3.set_branch("z9hG4bK776asdhds");
    via3.set_received("192.0.2.1");
    auto rport = jsip_parameter("rport" , "5060");
    via3.add_extension(rport);

    request.add_via(via1);
    request.add_via(via2);
    request.add_via(via3);

    auto contact_uri1 = jsip_uri(false,"home.com","jamal","",0);
    contact_uri1.set_param("Expires" , "3600");
    contact_uri1.set_param("q","0.5");
    auto contact_uri2 = jsip_uri(false,"work.com","jamal","",5063);
    contact_uri2.set_param("Expires" , "3600");
    contact_uri2.set_param("q","0.25");
    
    request.add_contact(contact_uri1 , "");
    request.add_contact(contact_uri2 , "Jamal Work");
    request.set_to_tag("9c85fb");
    request.add_to_param("rinstance","9c85fbcf36ba5304");
    request.set_from_tag("9erercfb");
    request.add_from_param("rinstance","9c85fbcf36ba5304");
    std::cout << request.to_string() << "\n";
}