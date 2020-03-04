#ifndef _JSIP_TYPES_H_
#define _JSIP_TYPES_H_

#include <any>
#include <map>
#include <string>
#include <ostream>
#include <vector>
#include <limits>
#include <cmath>
#include <cstring>
#include <iostream>
#include <sstream>
#include <sys/time.h>
#include <ctime>
#include <cstdlib>

#define HOST_EXCEPTION_MSG "Hostname is required"
#define PASSWORD_WITH_NO_USER_EXCEPTION_MSG "Password Cannot be set with out user"
#define INVALID_URI_EXCEPTION_MSG "Parsing Failed ,No Valid URI Found Parsed"
#define LR_VALUE_EXCEPTION_MSG "lr Parameter should not have paramter value"

#define URI_RESERVED_SET ";/?:@&=+$,"
#define URI_USER_RESERVED_SET ":@"
#define URI_PASS_RESERVED_SET ";/?:@"

#define JSIP_SIP_VERSION "SIP/2.0"
#define RFC3261_BRANCH_PREFIX "z9hG4bk"

#define CRLF "\r\n"
#define SP " "
#define LAQUOT "<"
#define RAQUOT ">"
#define DQUOTE "\""
static uint32_t next_cseq = 0;
class jsip_parameter;
struct jsip_via;
struct jsip_contact;

typedef std::string jsip_str_t;
typedef std::vector<jsip_parameter> jsip_param_list_t;
typedef std::vector<jsip_via> jsip_via_list_t;
typedef std::vector<jsip_contact> jsip_contact_list_t;
typedef enum jsip_method
{
    INVITE,
    ACK,
    OPTIONS,
    BYE,
    CANCEL,
    REGISTER
}jsip_method_t;
typedef enum class jsip_info_code 
{
    Trying = 100,
    Ringing = 180,
    Call_Is_Being_Forwarded = 181,
    Queued = 182,
    Session_Progress = 183
}jsip_info_code_t;
typedef enum class jsip_success_code 
{
    OK = 200
}jsip_success_code_t;
typedef enum class jsip_redirect_code 
{
    Multiple_Choice = 300,
    Moved_Permanently = 301,
    Moved_Temporarily = 302,
    Use_Proxy = 305,
    Alternative_Service = 380

}jsip_redirect_code_t;
typedef enum class jsip_client_error_code
{
    Bad_Request = 400,
    Unauthorized = 401,
    Payment_required=402,
    Forbidden=403,
    Not_Found = 404,
    Method_Not_Allowed=405,
    Not_Acceptable=406,
    Proxy_Authentication_Required=407,
    Request_Timeout=408,
    Gone=410,
    Request_Entity_Too_Large=413,
    Request_URI_Too_Large=414,
    Unsupported_Media_Type=415,
    Unsupported_URI_Scheme=416,
    Bad_Extenstion = 421,
    Extension_Required = 422,
    Interval_Too_Brief=423,
    Temporarily_Unavailable=480,
    Transaction_Does_Not_Exists=481,
    Loop_Detected=482,
    Too_Many_Hops=483,
    Address_Incomplete=484,
    Ambiguous=485,
    Busy_Here=486,
    Request_Terminated=487,
    Not_Acceptable_Here=488,
    Request_Pending=491,
    Undecipherable=493

}jsip_client_error_code;
typedef enum class jsip_server_error_code
{
    Server_Internal_Error=500,
    Not_Implemented=501,
    Bad_Gateway=502,
    Service_Unavailable=503,
    Service_Time_Out=504,
    SIP_Version_Not_Supported=505,
    Message_Too_Large=513
}jsip_server_error_code_t;
typedef enum class jsip_global_failure_code
{
    Busy_Everywhere = 600,
    Decline = 603,
    Does_Not_Exist_Anywhere=604,
    Not_Acceptable=606
}jsip_global_failure_code_t;
static inline void randomize_cseq()
{
    std::srand(std::time(0));
    next_cseq = (uint32_t)(std::rand() % 4000) + 1;
}
static jsip_str_t convert_to_escaped_string(const char* unescaped_string , const char* reserved_set)
{
    std::stringstream escaped_string_stream;
    char *unescaped_string_tracker = (char *)unescaped_string;
    auto parser = std::strpbrk(unescaped_string , reserved_set);
    while( parser != nullptr)
    {
        auto parsed_length =  parser - unescaped_string_tracker;
        escaped_string_stream << jsip_str_t(unescaped_string_tracker ,unescaped_string_tracker + parsed_length);
        escaped_string_stream << "%";
        escaped_string_stream << std::hex << int(parser[0]);
        unescaped_string_tracker= (char *)parser + 1;
        parser = std::strpbrk(unescaped_string_tracker , reserved_set);
        if(parser == nullptr)
        {
            escaped_string_stream << unescaped_string_tracker;
        }
    }
    jsip_str_t escaped_string = escaped_string_stream.str();
    return escaped_string == "" ? unescaped_string : escaped_string;
}; 
static inline uint32_t get_next_cseq()
{
    return next_cseq++;
}
/*
cryptographic functions to generated random string 
static uint32_t timeUniquifier()
static jsip_str_t globallyUniqueId(const char *start)
source : https://github.com/RangeNetworks/openbts
*/
static uint32_t timeUniquifier()
{
	struct timeval now;
	gettimeofday(&now,NULL);
	return ((now.tv_sec&0xffff)<<16) + (now.tv_usec/16);	// 32 bit number that changes every 15-16 usecs.
}

static jsip_str_t globallyUniqueId(const char *start , uint8_t size)
{
	// This is a a globally unique callid.
	char buf[size];
	snprintf(buf,size,"%s%x-%x",start,timeUniquifier(),(unsigned)(0xffffffff&random()));
	return jsip_str_t(buf);
}
static jsip_str_t get_method_str(jsip_method_t method){
    switch (method)
    {
        case jsip_method_t::INVITE:
            return "INVITE";
        case jsip_method_t::ACK:
            return "ACK";
        case jsip_method_t::REGISTER:
            return "REGISTER";
        case jsip_method_t::CANCEL:
            return "CANCEL";
        case jsip_method_t::BYE:
            return "BYE";
        case jsip_method_t::OPTIONS:
            return "OPTIONS";
        default:
            return "";
    }
}
class jsip_parameter
{
    private:
        std::pair<jsip_str_t , jsip_str_t> kv_pair;
    public:
        jsip_parameter();
        jsip_parameter(const jsip_str_t key, const jsip_str_t value);
        ~jsip_parameter() = default;

        inline jsip_str_t get_param_name(){ return this->kv_pair.first;};
        inline jsip_str_t get_value(){ return this->kv_pair.second;};

        inline jsip_str_t to_string()
        {
            return  kv_pair.first + "=" + kv_pair.second;
        };
        bool operator==(const jsip_parameter& B);
        bool is_set();
};
class jsip_uri
{
    private:
        jsip_str_t scheme , host , user , password;
        uint16_t port ;
        bool lr_param = false;
        uint8_t  ttl_param= '\0';
        jsip_parameter user_param , maddr_param  , transport_param , method_param;
        jsip_param_list_t other_param;
        jsip_param_list_t headers;
    public:
        jsip_uri()=default;
        jsip_uri(
            const bool _is_secure ,
            const jsip_str_t _host ,
            const jsip_str_t _user,
            const jsip_str_t _password ,
            const uint16_t _port);
        ~jsip_uri() = default;
        bool operator==(const jsip_uri& B);
        void set_scheme(bool _is_secure );
        void set_host(jsip_str_t _host );
        void set_user(jsip_str_t _user );
        void set_password(jsip_str_t _password );
        void set_port(uint16_t _port );
        void set_param(jsip_str_t param_name , jsip_str_t param_value);
        void inline set_lr_param(bool lr_value){ this->lr_param = lr_value; };
        void inline set_ttl_param(uint8_t ttl_value) { this->ttl_param = ttl_value ;};
        void add_header(jsip_str_t header_name , jsip_str_t header_value);

        inline jsip_str_t get_scheme(){return this->scheme;};
        inline bool is_secure(){ return this->get_scheme() == "sips";};
        inline bool get_lr_param() { return this->lr_param; }
        inline uint8_t get_ttl_param() { return this->ttl_param; }

        jsip_str_t to_string();
};
class jsip_parser
{
    protected:
        char *curr_char;
        char *parse_buffer;
        const char* delimit_set;
    public:
        jsip_parser(const char* buffer);
        ~jsip_parser(){free(parse_buffer);};
        jsip_str_t parse_token(const char* delimiter);
        virtual void parse(){};
};
class jsip_uri_parser : public jsip_parser
{
    private:
        const char *param_set = ";?> \t\f";
        const char *header_set = "&> \t\f";
        jsip_uri *sip_uri;
    public:
        jsip_uri_parser(const char* buffer) : jsip_parser{buffer} {};
        ~jsip_uri_parser(){} ;
        void parse_scheme();
        void parse() override;
        jsip_uri get_uri(){ return *this->sip_uri;};
};
struct jsip_via
{
    const jsip_str_t prtocol_name = "SIP";
    const jsip_str_t protocol_version = "2.0";
    jsip_str_t transport;
    jsip_str_t sent_host;
    uint16_t host_port;
    uint8_t ttl;
    jsip_str_t maddr;
    jsip_str_t received;
    jsip_str_t branch;
    jsip_param_list_t extensions;

     inline void set_transport(jsip_str_t _transport){ this->transport = _transport;};
     inline void set_sent_host(jsip_str_t _sent_host){ this->sent_host = _sent_host;};
     inline void set_host_port(uint16_t _host_port){ this->host_port = _host_port;};
     inline void set_ttl(uint8_t _ttl){ this->ttl = _ttl;};
     inline void set_maddr(jsip_str_t _maddr){ this->maddr = _maddr;};
     inline void set_received(jsip_str_t _received){ this->received = _received;};
     inline void set_branch(jsip_str_t _branch){ this->branch = _branch;};
    void add_extension(jsip_str_t extension_name , jsip_str_t extension_value ){
        auto extension = jsip_parameter(extension_name , extension_value);
        this->extensions.emplace_back(extension);
    };
     inline void add_extension(jsip_parameter extension){
        this->extensions.emplace_back(extension);
    };
    jsip_str_t to_string(){
        jsip_str_t via_str =  "Via: ";
        via_str += ( this->prtocol_name  + "/" + this->protocol_version + "/" + this->transport + SP );
        via_str += ( this->sent_host + (this->host_port == 0 ? "" : ":" + std::to_string(this->host_port)));
        if(this->ttl != 0){
            via_str += (";ttl=" + std::to_string(this->ttl));
        }
        if(this->maddr != ""){
            via_str += (";maddr=" + this->maddr);
        }
        if(this->received != ""){
            via_str += (";received=" + this->received);
        }
        if(this->branch != ""){
            via_str += (";branch=" + this->branch);
        }
        for( auto extension:this->extensions){
            via_str += (";" + extension.to_string());
        }
        return via_str;
    }
};
struct jsip_contact
{
    jsip_str_t display_name;
    jsip_uri uri;
    jsip_contact(jsip_uri uri , jsip_str_t display_name){ this->uri = uri ; this->display_name = display_name ;};
    jsip_str_t to_string(){
        jsip_str_t contact_uri_str = "Contact: ";
        if(display_name != ""){
            contact_uri_str += ( DQUOTE + display_name + DQUOTE + SP) ;
        } 
        contact_uri_str += LAQUOT + uri.to_string() + RAQUOT ;
        return contact_uri_str;
    }
};
class jsip_request
{
    private:
        jsip_method_t method;
        jsip_uri request_uri;
        jsip_str_t version = JSIP_SIP_VERSION;
        jsip_str_t call_id;
        jsip_str_t to_header;
        jsip_str_t to_tag;
        jsip_param_list_t to_params;
        jsip_str_t from_header;
        jsip_str_t from_tag;
        jsip_param_list_t from_params;
        uint32_t cseq_num;
        jsip_method_t cseq_method;
        int max_forwards;
        jsip_via_list_t vias;
        jsip_contact_list_t contacts;
    public:
        jsip_request(
            jsip_method_t _method,
            jsip_uri request_uri,
            jsip_str_t call_id,
            jsip_str_t to , 
            jsip_str_t to_tag,
            jsip_str_t from ,
            jsip_str_t from_tag ,
            jsip_method_t cseq_method,
            uint32_t cseq_num,
            int max_forwards 
        );
        ~jsip_request() = default;
        jsip_str_t to_string();
        void add_via(jsip_via via);
        inline void set_to_tag(jsip_str_t tag){ this->to_tag = tag;};
        inline void set_from_tag(jsip_str_t tag){ this->from_tag = tag;};
        void add_to_param(jsip_parameter param);
        void add_to_param(jsip_str_t param_name , jsip_str_t param_value);
        void add_from_param(jsip_parameter param);
        void add_from_param(jsip_str_t param_name , jsip_str_t param_value);
        void add_contact(jsip_uri uri , jsip_str_t display_name) {
            auto contact = jsip_contact(uri,display_name);
            this->contacts.emplace_back(contact);
        };

};
#endif