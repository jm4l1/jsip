#include "../include/jsip_types.h"
jsip_parameter::jsip_parameter(){
    kv_pair = std::make_pair("","");
}
jsip_parameter::jsip_parameter(const jsip_str_t key, const jsip_str_t value){
    kv_pair = std::make_pair(key , value);
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
    if(_host == "")
    {
        throw(HOST_EXCEPTION_MSG);
    }
    if(_user == "")
    {
        if(_password != "")
        {
            throw(PASSWORD_WITH_NO_USER_EXCEPTION_MSG);
        }
    }
    if(_is_secure)
        this->scheme = "sips";
    else
        this->scheme = "sip";

    this->host = _host;
    this->user = convert_to_escaped_string(_user.c_str() , URI_USER_RESERVED_SET);
    this->password = convert_to_escaped_string(_password.c_str() , URI_PASS_RESERVED_SET);
    this->port = _port;
    this->ttl_param= false;
}
bool jsip_uri::operator==(const jsip_uri& B){
    if( strcasecmp(this->scheme.c_str() , B.scheme.c_str()) != 0)
        {
            return false;
        }
    if(
        (this->user != B.user) ||
        ( strcasecmp(this->host.c_str() , B.host.c_str()  ) != 0 ) ||
        (this->password != B.password) ||
        (this->port != B.port)
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
void jsip_uri::set_scheme(bool _is_secure ){
    this->scheme = _is_secure ? "sips" : "sip";
    std::cout << this->scheme << "\n";
}
void jsip_uri::set_host(jsip_str_t _host ){
    this->host = _host;
}
void jsip_uri::set_user(jsip_str_t _user ){
    this->user = _user;
}
void jsip_uri::set_password(jsip_str_t _password ){
    this->password = _password;
}
void jsip_uri::set_port(uint16_t _port ){
    this->port = _port;
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
    if(std::strpbrk(header_value.c_str() , " ") != nullptr)
    {//value has a space
        header_value = "\"" + header_value  + "\"";
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
    if(this->ttl_param != '\0')
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
jsip_parser::jsip_parser(const char* buffer)
{
    curr_char = (char *)std::calloc(1,strlen(buffer));
    parse_buffer = (char *)std::calloc(1,strlen(buffer));
    std::memset(curr_char,0,strlen(buffer));
    std::memcpy(curr_char , buffer , strlen(buffer));
    std::memset(parse_buffer,0,strlen(buffer));
    std::memcpy(parse_buffer , buffer , strlen(buffer));
};
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
{//sip uri := scheme:[user[:password]@]host[:port][;uri-paramters][?headers]
    jsip_str_t host = "";
    jsip_str_t password = "";
    jsip_str_t user = "";
    uint16_t port = 0;
    bool is_secure = false;
    jsip_str_t uri_paramters;
    jsip_str_t uri_headers;
    //scheme:[user[:password]@]host[:port][;uri-paramters][?headers]
    std::cout << "sip uri to parse is " <<  curr_char << "\n";
    if(strncasecmp((curr_char) , "sip:" , 4) == 0)
    { //sip uri scheme
        curr_char += 4;
    }
    else if(strncasecmp(curr_char , "sips:" , 5) == 0)
    {//sips uri scheme
        curr_char += 5;
        is_secure = true;
    }
    else
    {//unknown uri scheme
        std::cout << "Unknown uri scheme\n";
        return;
    }
    //uri-parmaters ::= uri-param / ;uri-parameters]
    //headers ::= header / &headers
    if(curr_char == nullptr)
    {   
        throw(INVALID_URI_EXCEPTION_MSG);
    }
    //[user[:password]@]host[:port][;uri-paramters][?headers]
    auto userinfo =  parse_token("@");
    if(userinfo != "")
    {//uri has user info
        const auto user_end = std::strpbrk(userinfo.c_str(),":");
        if(user_end == nullptr){
            user = userinfo;
        }
        else{
            user = jsip_str_t(userinfo.c_str() , user_end);
            password = user_end + 1;
        }
        curr_char++;
    }
    //host[:port][;uri-paramters][?headers]
    host =  parse_token(":;?");
    this->sip_uri = new jsip_uri(is_secure  , host , user, password , 0 );
    if( curr_char != nullptr)
    { //string trailing the host
        if(curr_char[0] == ':')
        {   //port exists
            curr_char++;
             try
             {
                // auto curr_char_cpy = curr_char;
                auto port_part = parse_token(";?\0");
                if(port_part == "")
                {// nothing tailing port
                    if(curr_char[0] == ';')
                        goto process_params;
                    if(curr_char[0] == '?')
                        goto process_headers;
                    port_part = curr_char ;
                    curr_char += strlen(port_part.c_str());
                }
                port = (uint16_t)std::stoi(port_part);
                this->sip_uri->set_port(port);
             }
             catch(const std::exception& e)
             {
                 std::cerr << e.what() << '\n';
                 return;
             }
             
        }
        process_params:
            //[;uri-paramters][?headers]
            while (curr_char[0] == ';')
            {
                curr_char++;
                auto token = parse_token(";?");
                if(token == "")
                {
                    token = curr_char;
                }
                auto equal_char = std::strpbrk(token.c_str() ,"=");
                if(equal_char== nullptr)
                {
                    if(strcasecmp(token.c_str() , "lr") == 0)
                    {
                        this->sip_uri->set_lr_param(true);
                    }
                    else
                    {
                        this->sip_uri->set_param(token , "");
                    }
                }
                else
                {
                    auto param_name = jsip_str_t(token.c_str() , equal_char);
                    auto param_value = jsip_str_t(equal_char + 1 , equal_char + token .length());
                    if(strcasecmp(param_name.c_str() , "ttl") == 0)
                    {
                        this->sip_uri->set_ttl_param((uint8_t)stoi(param_value));
                    }
                    else if(strcasecmp(token.c_str() , "lr") == 0)
                    {
                        throw(LR_VALUE_EXCEPTION_MSG);
                    }
                    else
                    {
                        this->sip_uri->set_param(param_name , param_value);
                    }
                }
                
            }
        process_headers:
            //[?headers]
            while(curr_char[0] == '?' || curr_char[0] == '&' )
            {
                curr_char++; 
                auto token = parse_token("&");
                if(token == "")
                {
                    token = curr_char;
                }
            }
    }
};

jsip_request::jsip_request(
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
)
{
    this->method = _method;
    this->request_uri = request_uri;
    this->call_id = call_id;
    this->to_header = to;
    this->from_tag = to_tag;
    this->from_header = from;
    this->from_tag = from_tag;
    this->cseq_method = cseq_method;
    this->cseq_num = cseq_num;
    this->max_forwards = max_forwards;
}
void jsip_request::add_via(jsip_via via)
{
    this->vias.emplace_back(via);
};
void jsip_request::add_to_param(jsip_parameter param)
{
    this->to_params.emplace_back(param);
};
void jsip_request::add_to_param(jsip_str_t param_name , jsip_str_t param_value)
{
    auto param = jsip_parameter(param_name, param_value);
    this->to_params.emplace_back(param);
};
void jsip_request::add_from_param(jsip_parameter param)
{
    this->from_params.emplace_back(param);
};
void jsip_request::add_from_param(jsip_str_t param_name , jsip_str_t param_value)
{
    auto param = jsip_parameter(param_name, param_value);
    this->from_params.emplace_back(param);
};
jsip_str_t jsip_request::to_string()
{
    jsip_str_t request_str = "";
    jsip_str_t request_line = get_method_str(this->method) + SP + this->request_uri.to_string() + SP + JSIP_SIP_VERSION + CRLF;

    
    request_str += request_line;
    for( auto via:vias)
    {
        request_str += via.to_string();
        request_str += CRLF;
    }
    request_str += ("Max-Forwards: " + std::to_string(this->max_forwards) + CRLF ) ;
    if(contacts.size() == 0)
    {
        request_str += "Contact: <*>";
        request_str += CRLF;
    }
    else
    {
        for(auto contact:contacts)
        {
            request_str += contact.to_string();
            request_str += CRLF;
        }
    }
    
    
    request_str += ( "TO: " + this->to_header+ (this->to_tag != "" ? ";tag=" + this->to_tag : ""));
    for( auto param:this->to_params)
    {
        request_str += ";" + param.to_string();
    }
    request_str += CRLF;
    request_str += ( "FROM: " + this->from_header+ (this->from_tag != "" ? ";tag=" + this->from_tag : ""));
    for( auto param:this->from_params)
    {
        request_str += ";" + param.to_string();
    }
    request_str += CRLF;
    request_str += ("Call-ID:" + this->call_id + CRLF);
    request_str += ("CSeq : " + std::to_string(this->cseq_num) + SP +  get_method_str(this->cseq_method) + CRLF);
    request_str += CRLF;

    return request_str;
}