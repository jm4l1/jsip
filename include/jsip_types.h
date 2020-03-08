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
#define UNKNOWN_METHOD_EXCEPTION_MESSAGE "Method Type Not Supported"
#define REQUEST_PARSE_EXEPTION_MSG "Parsing Request Failed , Malformed Request"
#define VIA_PARSER_EXCEPTION_MSG "Parsing Via Failed"
#define ADDR_SPEC_PARSE_EXEPTION_MSG "Parsing Addr Spec Failed"
#define CSEQ_NUM_EXCEPTION_MSG "Invalid Type provided for CSeq Number , Number Expected"
#define UNKNOWN_URI_EXCEPTION_MSG "Unknown URI Scheme"

#define URI_RESERVED_SET ";/?:@&=+$,"
#define URI_USER_RESERVED_SET ":@"
#define URI_PASS_RESERVED_SET ";/?:@"

#define JSIP_SIP_VERSION "SIP/2.0"
#define RFC3261_BRANCH_PREFIX "z9hG4bk"


#define COLON ":"
#define COMMA ','
#define CRLF "\r\n"
#define DQUOTE '\"'
#define EQUAL '='
#define LAQUOT '<'
#define RAQUOT ">"
#define SEMI ';'
#define SLASH "/"
#define SP " "
#define STAR '*'

static uint32_t next_cseq = 0;
class jsip_parameter;
struct jsip_via;
struct jsip_addr_spec;
struct jsip_range;
typedef enum jsip_method
{
    INVITE,
    ACK,
    OPTIONS,
    BYE,
    CANCEL,
    REGISTER,
    NOTIFY,
    INFO
}jsip_method_t;

typedef std::string jsip_str_t;
typedef std::stringstream jsip_strstream_t;
typedef std::vector<jsip_parameter> jsip_param_list_t;
typedef std::vector<jsip_via> jsip_via_list_t;
typedef std::vector<jsip_addr_spec> jsip_addr_spec_list_t;
typedef std::vector<jsip_method_t> jsip_method_list_t;
typedef std::vector<jsip_range> jsip_range_list_t;
typedef std::vector<jsip_str_t> jsip_str_list_t;
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
static void trim_string(jsip_str_t *string)
{
    auto first_nws = string->find_first_not_of(' ');
    if(first_nws != jsip_str_t::npos)
    {
        string->erase(string->begin(), string->begin() + (first_nws));
    }
    auto last_nws = string->find_last_not_of(' ');
    if(last_nws != jsip_str_t::npos)
    {
        string->erase(string->begin() + last_nws + 1  , string->end());
    }
}
static jsip_str_t get_next_token(jsip_str_t *string , jsip_str_t delimiter)
{
    jsip_str_t token;
    auto first_ws = string->find_first_of(delimiter);
    if(first_ws == jsip_str_t::npos){
        token = *string;
        string->erase(string->begin(),string->end());
        *string = "";
        return token;
    }
    token = jsip_str_t(string->begin(), string->begin() + first_ws);
    string->erase(string->begin(), string->begin() + first_ws + 1);
    return token;
}
static jsip_str_t get_next_token(jsip_str_t *string , const char delimiter)
{
    jsip_str_t token;
    auto first_ws = string->find_first_of(delimiter);
    if(first_ws == jsip_str_t::npos){
        token = *string;
        string->erase(string->begin(),string->end());
        *string = "";
        return token;
    }
    token = jsip_str_t(string->begin(), string->begin() + first_ws);
    string->erase(string->begin(), string->begin() + first_ws + 1);
    return token;
}
/*
cryptographic functions to generated random string 
static uint32_t timeUniquifier()
static jsip_str_t globallyUniqueId(const char *start)
source : https://github.com/RangeNetworks/openbts
*/
static uint32_t time_uniquifier()
{
	struct timeval now;
	gettimeofday(&now,NULL);
	return ((now.tv_sec&0xffff)<<16) + (now.tv_usec/16);	// 32 bit number that changes every 15-16 usecs.
}
static jsip_str_t random_string(jsip_str_t start , uint8_t len)
{
	// The odds of one of these colliding is vanishingly small.
	// (pat) Actually, the odds are pretty good (like, near unity) unless you call srandom before calling random.
	uint64_t r1 = random();
	uint64_t r2 = random();
	uint64_t val = (r1<<32) + r2;
	jsip_str_t rand_string;
	
	// map [0->26] to [a-z] 
	rand_string=start;
    int k = 0;
	while( k < len)
    {
        auto x = val% 177 + '0' ;
        if(!isalnum(x))
        {
		    val = val >> 2;
            continue;
        }
		rand_string.push_back(x);
		val = val >> 4;
        k++;
	}
	return rand_string;
}

static jsip_str_t make_tag(uint8_t len)
{
	return random_string("", len);
}

static jsip_str_t make_branch(uint8_t len)
{
	// RFC3261 17.2.3: The branch parameter should begin with the magic string "z9hG4bK" to
	// indicate compliance with this specification.
	return random_string(RFC3261_BRANCH_PREFIX , len);
}
static jsip_str_t globallyUniqueId(const char *start , uint8_t size)
{
	// This is a a globally unique callid.
	char buf[size];
	snprintf(buf,size,"%s%x-%x",start,time_uniquifier(),(unsigned)(0xffffffff&random()));
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
        case jsip_method_t::NOTIFY:
            return "NOTIFY";
        case jsip_method_t::INFO:
            return "INFO";
        default:
            return "";
    }
}
static jsip_method_t get_method_from_str(jsip_str_t method_str){
    if(method_str == "INVITE")
    {
        return jsip_method_t::INVITE;
    }
    if(method_str == "ACK")
    {
        return jsip_method_t::ACK;
    }
    if(method_str == "REGISTER")
    {
        return jsip_method_t::REGISTER;
    }
    if(method_str == "CANCEL")
    {
        return jsip_method_t::CANCEL;
    }
    if(method_str == "BYE")
    {
        return jsip_method_t::BYE;
    }
    if(method_str == "OPTIONS")
    {
        return jsip_method_t::OPTIONS;
    }
    if(method_str == "NOTIFY")
    {
        return jsip_method_t::NOTIFY;
    }
    if(method_str == "INFO")
    {
        return jsip_method_t::INFO;
    }
    throw(UNKNOWN_METHOD_EXCEPTION_MESSAGE);
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
struct jsip_addr_spec
{
    jsip_str_t display_name;
    jsip_uri uri;
    jsip_param_list_t params;
    bool remove_bindings;
    jsip_addr_spec()=default;
    jsip_addr_spec(jsip_uri uri , jsip_str_t display_name){ this->uri = uri ; this->display_name = display_name ;};
    jsip_str_t to_string(){
        if(this->remove_bindings)
        {
            return "*";
        }
        jsip_str_t contact_uri_str = "";
        auto uri_str =uri.to_string();
        if(display_name != ""){
            contact_uri_str += ( DQUOTE + display_name + DQUOTE + SP) ;
            contact_uri_str += LAQUOT + uri_str + RAQUOT ;
        }
        else if(strpbrk(uri_str.c_str() , ",;?") != nullptr)
        {
            contact_uri_str += LAQUOT + uri_str + RAQUOT ;
        }
        else
        {
            contact_uri_str += uri_str;
        }

        for(auto param:params)
        {
            contact_uri_str += SEMI;
            contact_uri_str += param.to_string();
        }
        return contact_uri_str;
    }
    void add_param(jsip_parameter param){
        this->params.emplace_back(param);
    }
    void add_param(jsip_str_t param_name ,jsip_str_t param_value ){
        auto param = jsip_parameter(param_name , param_value);
        this->params.emplace_back(param);
    }
    void set_remove_bindings(bool _remove_bindings)
    {
        this->remove_bindings = _remove_bindings;
    }
};
struct jsip_range
{
    jsip_str_t range_id;
    jsip_parameter range_param;

    jsip_range()=default;
    jsip_range( jsip_str_t _id , jsip_parameter _param ):range_id(_id),range_param(_param){};
    ~jsip_range()=default; 
    jsip_str_t to_string(){
        return this->range_id + COMMA + this->range_param.to_string();
    };
};
class jsip_message
{
    protected:
        jsip_range_list_t accept_header;
        jsip_range_list_t accept_encoding_header;
        jsip_range_list_t accept_language_header;
        jsip_range_list_t alert_info_header;
        jsip_method_list_t allow_header;
        jsip_str_t call_id;
        jsip_range_list_t call_info_header;
        jsip_addr_spec_list_t contacts;
        jsip_range_list_t content_disposition_header;
        jsip_range_list_t content_encoding_header;
        int content_length;
        jsip_range_list_t content_type_header;
        uint32_t cseq_num;
        jsip_method_t cseq_method;
        jsip_str_t date;
        int expires = -1;
        jsip_addr_spec from_header;
        jsip_str_t from_tag;
        jsip_param_list_t from_params;
        jsip_str_t mime_version_header;
        jsip_str_t organisation_header;
        jsip_addr_spec_list_t record_route_header;
        jsip_addr_spec reply_to_header;
        jsip_str_list_t require_header;
        jsip_str_list_t supported_header;
        jsip_str_t time_stamp;
        jsip_addr_spec to_header;
        jsip_str_t to_tag;
        jsip_param_list_t to_params;
        jsip_via_list_t vias;
        
    public:
        jsip_message() = default;
        ~jsip_message() = default;
        jsip_str_t to_string();
        virtual jsip_str_t start_line_to_string(){ return "";};
        virtual jsip_str_t message_specific_headers_to_string(){return "";};
        void add_accept(jsip_range accept_range)
        {
            this->accept_header.emplace_back(accept_range);
        };
        void add_accept(jsip_str_t media_range , jsip_parameter accept_param)
        {
            auto accept_range = jsip_range(media_range,accept_param);
            this->accept_header.emplace_back(accept_range);
        };
        void add_accept_encoding(jsip_range accept_encoding_range)
        {
            this->accept_encoding_header.emplace_back(accept_encoding_range);
        };
        void add_accept_encoding(jsip_str_t encoding , jsip_parameter accept_encoding_param)
        {
            auto accept_encoding_range = jsip_range(encoding,accept_encoding_param);
            this->accept_encoding_header.emplace_back(accept_encoding_range);
        };
        void add_accept_language(jsip_range accept_language_range)
        {
            this->accept_language_header.emplace_back(accept_language_range);
        };
        void add_accept_language(jsip_str_t language , jsip_parameter accept_language_param)
        {
            auto accept_language_range = jsip_range(language,accept_language_param);
            this->accept_language_header.emplace_back(accept_language_range);
        };
        void add_alert_info(jsip_range alert_info_range)
        {
            this->alert_info_header.emplace_back(alert_info_range);
        };
        void add_alert_info(jsip_str_t alert_info_uri , jsip_parameter alert_info_param)
        {
            auto alert_info_range = jsip_range(alert_info_uri,alert_info_param);
            this->alert_info_header.emplace_back(alert_info_range);
        };
        void add_allow_method(jsip_method_t method);
        void set_call_id_header(jsip_str_t call_id_value);
        void add_call_info(jsip_range call_info_range)
        {
            this->call_info_header.emplace_back(call_info_range);
        };
        void add_call_info(jsip_str_t call_info_uri , jsip_parameter call_info_param)
        {
            auto call_info_range = jsip_range(call_info_uri,call_info_param);
            this->call_info_header.emplace_back(call_info_range);
        };
        void add_contact(jsip_addr_spec contact);
        void add_contact(jsip_uri uri , jsip_str_t display_name);
        void add_content_disposition(jsip_range content_disposition_range)
        {
            this->content_disposition_header.emplace_back(content_disposition_range);
        };
        void add_content_disposition(jsip_str_t disp_type , jsip_parameter content_disposition_param)
        {
            auto content_disposition_range = jsip_range(disp_type,content_disposition_param);
            this->content_disposition_header.emplace_back(content_disposition_range);
        };
        void add_content_encoding(jsip_range content_encoding_range)
        {
            this->content_encoding_header.emplace_back(content_encoding_range);
        };
        void add_content_encoding(jsip_str_t disp_type , jsip_parameter content_encoding_param)
        {
            auto content_encoding_range = jsip_range(disp_type,content_encoding_param);
            this->content_encoding_header.emplace_back(content_encoding_range);
        };
        void set_content_length(int _length)
        {
            this->content_length = _length;
        }
        void add_content_type(jsip_range content_type_range)
        {
            this->content_type_header.emplace_back(content_type_range);
        };
        void add_content_type(jsip_str_t disp_type , jsip_parameter content_type_param)
        {
            auto content_type_range = jsip_range(disp_type,content_type_param);
            this->content_type_header.emplace_back(content_type_range);
        };
        void set_cseq_header(jsip_str_t cseq_value);
        void set_date_header(jsip_str_t _date)
        {
            this->date = _date;
        };
        inline void set_expires_header(int expires_value)
        {
            this->expires =expires_value ;
        };
        void set_from_header(jsip_uri uri , jsip_str_t display_name);
        void set_from_header(jsip_addr_spec from_uri);
        void add_from_param(jsip_str_t param_name , jsip_str_t param_value);
        void add_from_param(jsip_parameter param);
        void set_mime_version_header(jsip_str_t _mime_version)
        {
            this->mime_version_header = _mime_version;
        };
        void set_organisation_header(jsip_str_t _organisation)
        {
            this->organisation_header = _organisation;
        };
        void add_record_route(jsip_uri uri , jsip_str_t display_name)
        {
            auto record_route = jsip_addr_spec(uri,display_name);
            this->record_route_header.emplace_back(record_route);
        };
        void add_record_route(jsip_addr_spec record_route)
        {
            this->record_route_header.emplace_back(record_route);
        };
        void set_reply_to(jsip_uri uri , jsip_str_t display_name)
        {
            auto reply_to = jsip_addr_spec(uri,display_name);
            this->reply_to_header = reply_to ;
        };
        void set_reply_to(jsip_addr_spec reply_to)
        {
            this->reply_to_header = reply_to ;
        };
        void add_require(jsip_str_t option)
        {
            this->require_header.emplace_back(option);
        }
        void add_supported(jsip_str_t option)
        {
            this->supported_header.emplace_back(option);
        }
        void set_timestamp(jsip_str_t timestamp)
        {
            this->time_stamp = timestamp;
        }
        void set_to_header(jsip_uri uri , jsip_str_t display_name);
        void set_to_header(jsip_addr_spec to_uri);
        void add_to_param(jsip_str_t param_name , jsip_str_t param_value);
        void add_to_param(jsip_parameter param);
        inline void set_to_tag(jsip_str_t tag_value)
        {
            this->to_tag = tag_value;
        };
        inline void set_from_tag(jsip_str_t tag_value)
        {
            this->from_tag = tag_value;
        };
        void add_via(jsip_via via);

};
class jsip_request : public jsip_message
{
    private:
        jsip_method_t method;
        jsip_uri request_uri;
        jsip_str_t version = JSIP_SIP_VERSION;
        int max_forwards;

    public:
        jsip_request() = default;
        jsip_request(
            jsip_method_t method,
            jsip_uri request_uri,
            jsip_str_t call_id,
            jsip_method_t cseq_method,
            uint32_t cseq_num,
            int max_forwards 
        );
        ~jsip_request() = default;
        jsip_str_t start_line_to_string() override;
        jsip_str_t message_specific_headers_to_string() override;
        void set_request_method(jsip_method_t _method);
        void set_request_uri (jsip_uri request_uri);
        inline void set_max_forwards_header(int max_forwards_value)
        { 
            this->max_forwards =max_forwards_value ;
        };
};
class jsip_response : public jsip_message
{
    private:
        jsip_str_t version = JSIP_SIP_VERSION;
        
    public:
        jsip_response() = default;
        ~jsip_response() = default;
        // jsip_str_t start_line_to_string() override;
        // jsip_str_t message_specific_headers_to_string() override;
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
        inline jsip_str_t get_original_message(){ return this->parse_buffer;}
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
        inline jsip_uri get_uri(){ return *this->sip_uri;};
};
class jsip_request_parser : public jsip_parser
{
    private:
        jsip_request request;
    public:
        jsip_request_parser(const char* buffer) : jsip_parser{buffer} {};
        ~jsip_request_parser(){} ;
        void parse() override;
        void parse_request_line(jsip_str_t *curr_line);
        void parse_sip_header(jsip_str_t *curr_line);
        inline jsip_request get_request(){ return this->request;};
};
class jsip_via_parser : public jsip_parser
{
    private:
        jsip_via via;
    public:
        jsip_via_parser(const char* buffer) : jsip_parser{buffer} {};
        ~jsip_via_parser(){};
        void parse() override;
        inline jsip_via get_via(){ return this->via;};
};
class jsip_addr_spec_parser : public jsip_parser
{
    private:
        jsip_addr_spec addr_spec;
    public:
        jsip_addr_spec_parser(const char* buffer) : jsip_parser{buffer} {};
        ~jsip_addr_spec_parser(){};
        void parse() override;
        inline jsip_addr_spec get_addr_spec(){ return this->addr_spec;};
};
#endif