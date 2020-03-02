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
class jsip_parameter;

typedef std::string jsip_str_t;
typedef std::vector<jsip_parameter> jsip_param_list_t;

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

        inline jsip_str_t to_string();
        bool operator==(const jsip_parameter& B);
        bool is_set();
};
class jsip_uri
{
    private:
        jsip_str_t scheme , host , user , password;
        uint16_t port ;
        bool lr_param = false;
        uint8_t  ttl_param= NULL;
        jsip_parameter user_param , maddr_param  , transport_param , method_param;
        jsip_param_list_t other_param;
        jsip_param_list_t headers;
    public:
        jsip_uri(
            const bool _is_secure ,
            const jsip_str_t _host ,
            const jsip_str_t _user,
            const jsip_str_t _password ,
            const uint16_t _port);
        
        bool operator==(const jsip_uri& B);

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
        const char *curr_char;
        const char *parse_buffer;
        const char* delimit_set;
    public:
        jsip_parser(const char* buffer):curr_char(buffer),parse_buffer(buffer){};
        ~jsip_parser() = default ;
        jsip_str_t parse_token(const char* delimiter);
        virtual void parse(){};
};
class jsip_uri_parser : public jsip_parser
{
    private:
        const char *param_set = ";?> \t\f";
        const char *header_set = "&> \t\f";
    public:
        jsip_uri_parser(const char* buffer) : jsip_parser{buffer} {};
        ~jsip_uri_parser() = default ;
        void parse_scheme();
        void parse() override;
};
#endif