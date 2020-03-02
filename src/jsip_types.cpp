#include "../include/jsip_types.h"
jsip_parameter::jsip_parameter(){
    kv_pair = std::make_pair("","");
}
jsip_parameter::jsip_parameter(const jsip_str_t key, const jsip_str_t value){
    kv_pair = std::make_pair(key , value);
}
inline jsip_str_t jsip_parameter::to_string(){
    return  kv_pair.first + "=" + kv_pair.second;
}
bool jsip_parameter::operator==(const jsip_parameter& B){
    return this->kv_pair == B.kv_pair;
}
bool jsip_parameter::is_set()
{
    return kv_pair != std::make_pair(jsip_str_t(""),jsip_str_t(""));
}
jsip_uri::jsip_uri(
    const bool _is_secure ,
    const jsip_str_t _host ,
    const jsip_str_t _user,
    const jsip_str_t _password ,
    const uint16_t _port
)
{
    if(_is_secure)
        this->scheme = "sips";
    else
        this->scheme = "sip";
    this->host = _host;
    this->user = _user;
    this->port = _port;
    this->password = _password;
    this->ttl_param= false;
}
bool jsip_uri::operator==(const jsip_uri& B){
    if(this->scheme != B.scheme)
        {
            return false;
        }
    if(
        (this-> user != B.user) ||
        (this-> host != B.host) ||
        (this-> password != B.password) ||
        (this-> port != B.port)
    )
    {
        return false;
    }
    if(
        (! (this->user_param == B.user_param) ) || 
        (! (this->ttl_param == B.ttl_param) ) ||
        (! (this->method_param == B.method_param) ) ||
        (! (this->transport_param == B.transport_param) ) ||
        (! (this->maddr_param == B.maddr_param) )
    )
    {
        return false;
    }
    for( auto param:this->other_param){
        auto param_name = param.get_param_name();
        auto b_param = std::find_if(B.other_param.begin() , B.other_param.end() , [param_name ](jsip_parameter b_param){
            return param_name == b_param.get_param_name();
        });
        if(b_param != B.other_param.end())
        {
            if( !(param == *(b_param)) )
                return false;
        }
    }
    for( auto param:this->headers){
        auto param_name = param.get_param_name();
        auto b_param = std::find_if(B.other_param.begin() , B.other_param.end() , [param_name ](jsip_parameter b_param){
            return param_name == b_param.get_param_name();
        });
        if(b_param == B.other_param.end())
        {
            return false;
        }
        {
            if( !(param == *(b_param)) )
                return false;
        }
    }
    return true;
}
void jsip_uri::set_param(jsip_str_t param_name , jsip_str_t param_value)
{
    if(param_name == ""){
        //raise exception
        return;
    }
    if( param_name == "user" ){
        this->user_param = jsip_parameter(param_name , param_value);
        return;
    }
    if( param_name == "maddr" ){
        this->maddr_param = jsip_parameter(param_name , param_value);
        return;
    }
    if( param_name == "transport" ){
        this->transport_param = jsip_parameter(param_name , param_value);
        return;
    }
    if( param_name == "method" ){
        this->method_param = jsip_parameter(param_name , param_value);
        return;
    }
    auto param =  jsip_parameter(param_name , param_value);
    this->other_param.emplace_back(param);
}
void jsip_uri::add_header(jsip_str_t header_name , jsip_str_t header_value){
    if(header_name == "")
    {
        // generate exception
        return; 
    }
    auto header = jsip_parameter(header_name , header_value);
    this->headers.emplace_back(header);
}
jsip_str_t jsip_uri::to_string()
{
    jsip_str_t uri_string = this->scheme + ":";
    if(this->user != "")
    {
        uri_string += this->user;
        if(this->password != "")
            uri_string += ":" + this->password ;
        uri_string += "@";
    }
    uri_string += this->host;
    if(this->port > 0)
        uri_string += ":" + std::to_string(port) ;
    if(this->user_param.is_set())
        uri_string += ";" + this->user_param.to_string();
    if(this->transport_param.is_set())
        uri_string += ";" + this->transport_param.to_string();
    if(this->maddr_param.is_set())
        uri_string += ";" + this->maddr_param.to_string();
    if(this->method_param.is_set())
        uri_string += ";" + this->method_param.to_string();
    if(this->ttl_param != NULL)
        {
            uri_string += ";ttl=";
            uri_string += std::to_string(this->ttl_param);
        }
        std::for_each(this->other_param.begin() , this->other_param.end(), [&uri_string](jsip_parameter param){
        if(param.is_set())
            {
                if(param.get_value() == "")
                {
                    uri_string += ";" + param.get_param_name();
                }
                else
                {
                    uri_string += ";" + param.to_string();
                }
            }
        });
    if(this->lr_param)
        uri_string += ";lr";
    if(this->headers.begin() != this->headers.end()){
        uri_string += "?";
        auto first_header = (*this->headers.begin()) ;
        uri_string += first_header.to_string();
        std::for_each(this->headers.begin() + 1 , this->headers.end(), [&uri_string](jsip_parameter param){
                    uri_string += "&" + param.to_string();
        });
    }
    return uri_string;
}
jsip_str_t jsip_parser::parse_token(const char* delimiter_set){
    auto token_end = std::strpbrk(curr_char , delimiter_set);
    if(token_end == nullptr)
        return "";
    auto token = jsip_str_t(curr_char, (token_end - curr_char));
    curr_char = (token_end);
    return token;
}

void jsip_uri_parser::parse_scheme()
{
    if(strncasecmp((curr_char) , "sip:" , 4) == 0)
    { //sip uri scheme
        curr_char += 4;
    }
    else if(strncasecmp(curr_char , "sips:" , 5) == 0)
    {//sips uri scheme
        curr_char += 5;
    }
    else
    {//unknown uri scheme
        std::cout << "Unknown uri scheme\n";
        return;
    }
}
void jsip_uri_parser::parse()
{
    jsip_str_t scheme = "";
    jsip_str_t host = "";
    jsip_str_t password = "";
    jsip_str_t user = "";
    uint16_t port = 0;
    bool is_secure = false;

    //sip uri := scheme:[user[:password]]host[:port][;uri-paramters][?headers]
    this->parse_scheme();  //scheme ::= [ sip | sips ]
    //uri-parmaters ::= uri-param / ;uri-parameters]
    //headers ::= header / &headers
    if(curr_char == nullptr)
    {
        std::cout << "invalid uri\n";
        return;
    }
    auto userinfo =  parse_token("@");
    if(userinfo != "")
    {//uri has user info
        const auto user_end = std::strpbrk(userinfo.c_str(),":");
        if(user_end == nullptr){
            user = userinfo;
        }
        else{
            curr_char++;
            user = jsip_str_t(userinfo.c_str() , user_end);
            password = user_end ;
        }
    }
    std::cout << "After parsing userinfo  " << curr_char << '\n';
    auto hostpart =  parse_token(":;?");
    std::cout << "After parsing host part " << curr_char << '\n';
    if( curr_char != nullptr)
    { //string trailing the host
        if(curr_char[0] == ':')
        {   
            curr_char++;
             try
             {
                auto port_part = parse_token(";?\0").c_str();
                port = (uint16_t)std::stoi(port_part);
                std::cout << "After parsing port " << curr_char << '\n';
             }
             catch(const std::exception& e)
             {
                 std::cerr << e.what() << '\n';
                 return;
             }
             
        }
    }
};
