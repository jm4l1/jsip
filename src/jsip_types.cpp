#include "../include/jsip_types.h"
jsip_parameter::jsip_parameter(){
    kv_pair = std::make_pair("","");
}
jsip_parameter::jsip_parameter(const jsip_str_t key, const jsip_str_t value)
{
    kv_pair = std::make_pair(key , value);
}
bool jsip_parameter::operator==(const jsip_parameter& B)
{
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
bool jsip_uri::operator==(const jsip_uri& B)
{
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
void jsip_uri::set_scheme(bool _is_secure )
{
    this->scheme = _is_secure ? "sips" : "sip";
}
void jsip_uri::set_host(jsip_str_t _host )
{
    this->host = _host;
}
void jsip_uri::set_user(jsip_str_t _user )
{
    this->user = _user;
}
void jsip_uri::set_password(jsip_str_t _password )
{
    this->password = _password;
}
void jsip_uri::set_port(uint16_t _port )
{
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
void jsip_uri::add_header(jsip_str_t header_name , jsip_str_t header_value)
{
    if(header_name == "")
    {
        // generate exception
        return; 
    }
    if(std::strpbrk(header_value.c_str() , SP) != nullptr)
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
        uri_string += SEMI + this->user_param.to_string();
    if(this->transport_param.is_set())
        uri_string += SEMI + this->transport_param.to_string();
    if(this->maddr_param.is_set())
        uri_string += SEMI + this->maddr_param.to_string();
    if(this->method_param.is_set())
        uri_string += SEMI + this->method_param.to_string();
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
                    uri_string += SEMI + param.get_param_name();
                }
                else
                {
                    uri_string += SEMI + param.to_string();
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
jsip_str_t jsip_parser::parse_token(const char* delimiter_set)
{
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
        throw(UNKNOWN_URI_EXCEPTION_MSG);
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
        throw(UNKNOWN_URI_EXCEPTION_MSG);
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
void jsip_request::set_request_method(jsip_method_t _method)
{
    this->method = _method;
};
void jsip_request::set_request_uri (jsip_uri request_uri)
{
    this->request_uri = request_uri;
};
void jsip_message::set_to_header(jsip_uri uri , jsip_str_t display_name)
{
    auto to_uri = jsip_addr_spec(uri,display_name);
    this->to_header = to_uri;
};
void jsip_message::set_to_header(jsip_addr_spec to_uri){
    this->to_header = to_uri;
};
void jsip_message::set_from_header(jsip_uri uri , jsip_str_t display_name)
{
    auto from_uri = jsip_addr_spec(uri,display_name); 
    this->from_header = from_uri;
};
void jsip_message::set_from_header(jsip_addr_spec from_uri)
{
    this->from_header = from_uri;
};
void jsip_message::set_call_id_header(jsip_str_t call_id_value)
{
    this->call_id = call_id_value;
};
void jsip_message::set_cseq_header(jsip_str_t cseq_value)
{
    trim_string(&cseq_value);
    auto cseq_num = get_next_token(&cseq_value , SP);
    try{
        this->cseq_num = std::stoi(cseq_num);
    }
    catch(std::exception& e){
        throw(CSEQ_NUM_EXCEPTION_MSG);
    }
    trim_string(&cseq_value);
    this->cseq_method = get_method_from_str(cseq_value);
};
void jsip_message::add_via(jsip_via via)
{
    this->vias.emplace_back(via);
};
void jsip_message::add_to_param(jsip_parameter param)
{
    this->to_params.emplace_back(param);
};
void jsip_message::add_to_param(jsip_str_t param_name , jsip_str_t param_value)
{
    auto param = jsip_parameter(param_name , param_value);
    this->to_params.emplace_back(param);
};
void jsip_message::add_from_param(jsip_parameter param)
{
    this->from_params.emplace_back(param);
};
void jsip_message::add_from_param(jsip_str_t param_name , jsip_str_t param_value)
{
    auto param = jsip_parameter(param_name , param_value);
    this->from_params.emplace_back(param);
};        
void jsip_message::add_allow_method(jsip_method_t method)
{
    this->allow_header.emplace_back(method);
};
void jsip_message::add_contact(jsip_uri uri , jsip_str_t display_name)
{
    auto contact = jsip_addr_spec(uri,display_name);
    this->contacts.emplace_back(contact);
};
void jsip_message::add_contact(jsip_addr_spec contact)
{
    this->contacts.emplace_back(contact);
};
jsip_str_t jsip_message::to_string()
{
    jsip_str_t request_str = "";
    //start line
    request_str += this->start_line_to_string();
    //via header(s)
    for( auto via:vias)
    {
        request_str += via.to_string();
        request_str += CRLF;
    }
    //Contact(s)
    for(auto contact:contacts)
    {
        request_str += "Contact: ";
        request_str += contact.to_string();
        request_str += CRLF;
    }
    //TO header
    request_str += ( "To: " + this->to_header.to_string());
    if(to_tag != "")    
    {//To Tag
        request_str +=  SEMI;
        request_str += ("tag=" + to_tag);
    }
    for(auto param:to_params)
    {//To Params
        request_str += SEMI;
        request_str += param.to_string();
    };
    request_str += CRLF;
    //From Header
    request_str += ( "From: " + this->from_header.to_string());
    if(from_tag != "")
    {//From Tag
        request_str +=  SEMI;
        request_str += ("tag=" + from_tag);
    }
    for(auto param:from_params)
    {//From Header Params
        request_str += SEMI;
        request_str += param.to_string();
    };
    request_str += CRLF;
    //Call-ID
    request_str += ("Call-ID:" + this->call_id + CRLF);
    //CSeq
    request_str += ("CSeq : " + std::to_string(this->cseq_num) + SP +  get_method_str(this->cseq_method) + CRLF);
    //Expires
    if( this->expires != -1 )
    {
        request_str += ("Expires: " + std::to_string(this->expires) + CRLF );
    }
    request_str += this->message_specific_headers_to_string();
    if(!this->allow_header.empty())
    {
        request_str += "Allow: ";
        request_str +=  get_method_str(this->allow_header[0]);
        for(auto i =  this->allow_header.begin() + 1 ; i != this->allow_header.end() ; i++)
        {
            request_str += COMMA + (SP + get_method_str(*i));
        }
    }

    request_str += CRLF;
    return request_str;
}
jsip_request::jsip_request(
    jsip_method_t _method,
    jsip_uri request_uri,
    jsip_str_t call_id,
    jsip_method_t cseq_method,
    uint32_t cseq_num,
    int max_forwards 
)
{
    this->method = _method;
    this->request_uri = request_uri;
    this->call_id = call_id;
    this->cseq_method = cseq_method;
    this->cseq_num = cseq_num;
    this->max_forwards = max_forwards;
};
jsip_str_t jsip_request::start_line_to_string()
{
    //request line
    return get_method_str(this->method) + SP + this->request_uri.to_string() + SP + JSIP_SIP_VERSION + CRLF;
};
jsip_str_t jsip_request::message_specific_headers_to_string()
{
    jsip_str_t request_str = "";
    //Max-Forwards
    request_str += ("Max-Forwards: " + std::to_string(this->max_forwards) + CRLF ) ;
    return request_str;
}
void jsip_request_parser::parse_request_line(jsip_str_t *curr_line)
{
    //get request line first Method SP Request-URI SP SIP-Version
    auto token = get_next_token(curr_line , SP);
    jsip_method_t request_method;
    try{
        request_method = get_method_from_str(token);
        this->request.set_request_method(request_method);
    }
    catch(const std::exception& e){
        throw(REQUEST_PARSE_EXEPTION_MSG);
    }
    token = get_next_token(curr_line , SP);
    auto request_uri_parser = jsip_uri_parser(token.c_str());
    try{
        request_uri_parser.parse();
        this->request.set_request_uri(request_uri_parser.get_uri());
    }
    catch(const std::exception& e){
        throw(REQUEST_PARSE_EXEPTION_MSG);
    }
    token = get_next_token(curr_line , SP);
    if(token != JSIP_SIP_VERSION)
    {
        throw(REQUEST_PARSE_EXEPTION_MSG);
    }
}
void jsip_via_parser::parse()
{
    jsip_str_t buffer = curr_char;
    auto sent_protocol = get_next_token(&buffer,SP);
    auto protocol_name = get_next_token(&sent_protocol ,SLASH);
    auto protocol_version = get_next_token(&sent_protocol ,SLASH);
    if( protocol_name +SLASH+protocol_version != JSIP_SIP_VERSION){
        throw(VIA_PARSER_EXCEPTION_MSG);
    }
    auto transport= get_next_token(&sent_protocol ,SLASH);
    this->via.set_transport(transport);
    trim_string(&buffer);
    auto sent_by = get_next_token(&buffer,SEMI);
    auto sent_host = get_next_token(&sent_by,COLON);
    this->via.set_sent_host(sent_host);
    if(sent_by != "")
    {
        try{
            auto sent_port = (uint16_t)stoi(sent_by);
            this->via.set_host_port(sent_port);
        }
        catch(jsip_str_t e)
        {
            throw(VIA_PARSER_EXCEPTION_MSG);
        }
    }
    while(buffer != "")
    {
        auto token = get_next_token(&buffer,SEMI);
        auto param_name = get_next_token(&token,"=");
        auto param_value= token;
        if(param_name == "ttl")
        {
            this->via.set_ttl((uint8_t)stoi(param_value));
            continue;
        }
        if(param_name == "maddr")
        {
            this->via.set_maddr(param_value);
            continue;
        }
        if(param_name == "received")
        {
            this->via.set_received(param_value);
            continue;
        }
        if(param_name == "branch")
        {
            this->via.set_branch(param_value);
            continue;
        }
        this->via.add_extension(param_name ,param_value);
    }
};
void jsip_addr_spec_parser::parse()
{
    //jsip_addr_spec = ["display-name"] <jsip_uri>[;params]
    jsip_str_t buffer = curr_char;
    bool name_addr_form = false;
    trim_string(&buffer);
    if(buffer[0] == DQUOTE){
        buffer.erase(buffer.begin());
        auto display_name = get_next_token(&buffer , DQUOTE);
        this->addr_spec.display_name = display_name;
        name_addr_form = true;
    }
    trim_string(&buffer);
    if(name_addr_form)
    {
        if(buffer[0] != LAQUOT)
        {
            throw(ADDR_SPEC_PARSE_EXEPTION_MSG);
        } 
        if(strpbrk(buffer.c_str(),RAQUOT) == nullptr)
        {
            throw(ADDR_SPEC_PARSE_EXEPTION_MSG);
        }
    }
    jsip_str_t uri_string;
    if(buffer[0] == LAQUOT){
        buffer.erase(buffer.begin());
        uri_string = get_next_token(&buffer , RAQUOT);
    }
    else{
        uri_string = buffer;
    }
    auto uri_parser = jsip_uri_parser(uri_string.c_str());
    try
    {
        uri_parser.parse();
        this->addr_spec.uri = uri_parser.get_uri();
    }
    catch( jsip_str_t e)
    {
        throw(ADDR_SPEC_PARSE_EXEPTION_MSG);
    }
    trim_string(&buffer);
    if(!buffer.empty())
    {
        if((buffer.c_str())[0] != SEMI)
        {
            throw(ADDR_SPEC_PARSE_EXEPTION_MSG);
        }
    }
    buffer.erase(buffer.begin());
    while(!buffer.empty())
    {
        auto param = get_next_token(&buffer , SEMI);
        auto param_header = get_next_token(&param , EQUAL);
        this->addr_spec.add_param(param_header,param);
    }
}
void jsip_request_parser::parse_sip_header(jsip_str_t *curr_line)
{
    auto token = get_next_token(curr_line , COLON);
    auto header = token;
    trim_string(&header);
    trim_string(curr_line);
    if(header == "Via")
    {
        auto  via_parser = jsip_via_parser((*curr_line).c_str());
        try{
            via_parser.parse();
            this->request.add_via(via_parser.get_via());
            return;
        }
        catch(jsip_str_t e){
            throw(REQUEST_PARSE_EXEPTION_MSG) ;
        }
    }
    if(header == "To")
    {
        auto to_parser = jsip_addr_spec_parser((*curr_line).c_str());
        try{
            to_parser.parse();
            this->request.set_to_header(to_parser.get_addr_spec());
            return;
        }
        catch(jsip_str_t e){
            throw(REQUEST_PARSE_EXEPTION_MSG) ;
        }
    }
    if(header == "From")
    {
        auto from_parser = jsip_addr_spec_parser((*curr_line).c_str());
        try{
            from_parser.parse();
            this->request.set_from_header(from_parser.get_addr_spec());
            return;
        }
        catch(jsip_str_t e){
            throw(REQUEST_PARSE_EXEPTION_MSG) ;
        }
    }
    if(header == "Contact")
    {   //[ ( * / (  ( ["display-name"]<sip uri> / sip uri )  ( ;contact_params) ))]
        if((*curr_line)[0] == STAR )
        {
            auto contact = jsip_addr_spec();
            contact.set_remove_bindings(true);
            this->request.add_contact(contact);
            return;
        }
        else
        {
            auto contact_parser = jsip_addr_spec_parser((*curr_line).c_str());
            try{
                contact_parser.parse();
                this->request.add_contact(contact_parser.get_addr_spec());
                return;
            }
            catch(jsip_str_t e){
                throw(REQUEST_PARSE_EXEPTION_MSG) ;
            }
        }
        
    }
    if(header == "Max-Forwards")
    {
        try{
            this->request.set_max_forwards_header(stoi(*curr_line));
            return;
        }
        catch(jsip_str_t e){
            throw(REQUEST_PARSE_EXEPTION_MSG);
        }
    }
    if(header == "Call-ID")
    {
        this->request.set_call_id_header(*curr_line);
        return;
    }
    if(header == "CSeq")
    {   
        this->request.set_cseq_header(*curr_line);
        return;
    }
    if(header == "Expires")
    {
        try
        {
            auto expires = std::stoi(*curr_line);
            this->request.set_expires_header(expires);
            return;
        }
        catch(jsip_str_t e)
        {
            throw(REQUEST_PARSE_EXEPTION_MSG);
        }
    }
    if(header == "Allow")
    {
        while(!(*curr_line).empty()){
            auto method_str = get_next_token(curr_line, COMMA);
            trim_string(curr_line);
            try{
                auto method = get_method_from_str(method_str);
                this->request.add_allow_method(method);
            }
            catch(const char*){
                
            }
        }
        return;
    }
}
void jsip_request_parser::parse(){
    jsip_strstream_t buffer_stream ;
    jsip_str_t curr_line;
    buffer_stream << curr_char ;

    std::getline(buffer_stream,curr_line);
    trim_string(&curr_line);
    curr_line.erase( std::remove(curr_line.begin(),curr_line.end(), '\r'), curr_line.end() );
    this->parse_request_line(&curr_line);

    while(std::getline(buffer_stream,curr_line)) 
    {
        curr_line.erase( std::remove(curr_line.begin(),curr_line.end(), '\r'), curr_line.end() );
        trim_string(&curr_line);
        this->parse_sip_header(&curr_line);
    }
};