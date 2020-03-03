#include "catch.hpp"
#include "../include/jsip_types.h"

TEST_CASE("jsip_uri basic (no params) , (no headers) - success ")
{
    auto sip_uri = jsip_uri(false , "voip.digicelgroup.com","user","password",5060);
    jsip_str_t expected_uri = "sip:user:password@voip.digicelgroup.com:5060";
    REQUIRE(sip_uri.to_string() == expected_uri);
}
TEST_CASE("jsip_uri basic (no params) , (no headers) , (no password) -(success)")
{
    auto sip_uri = jsip_uri(false , "voip.digicelgroup.com","user","",5060);
    jsip_str_t expected_uri = "sip:user@voip.digicelgroup.com:5060";
    REQUIRE(sip_uri.to_string() == expected_uri);
}
TEST_CASE("jsip_uri basic sips (no params) , (no headers) , (no userinfo)  , (no port) -(success)")
{
    auto sip_uri = jsip_uri(true , "voip.digicelgroup.com","","",0);
    jsip_str_t expected_uri = "sips:voip.digicelgroup.com";
    REQUIRE(sip_uri.to_string() == expected_uri);
}
TEST_CASE("jsip_uri sips ( with params) , (no headers) , (no port) -(success)")
{
    auto sip_uri = jsip_uri(true , "voip.digicelgroup.com","user","password",0);
    sip_uri.set_lr_param(true);
    sip_uri.set_ttl_param(255);
    sip_uri.set_param("transport","tcp");
    jsip_str_t expected_uri = "sips:user:password@voip.digicelgroup.com;transport=tcp;ttl=255;lr";
    REQUIRE(sip_uri.to_string() == expected_uri);
}
TEST_CASE("jsip_uri sip ( no params) , (with headers) , (no port) -(success)")
{
    auto sip_uri = jsip_uri(true , "voip.digicelgroup.com","user","password",0);
    sip_uri.add_header("Method" , "INVITE");
    jsip_str_t expected_uri = "sips:user:password@voip.digicelgroup.com?Method=INVITE";
    REQUIRE(sip_uri.to_string() == expected_uri);
}
TEST_CASE("jsip_uri basic (no params) , (no headers) , missing domain - (throw exception) ")
{
    REQUIRE_THROWS_WITH(jsip_uri(false , "","user","password",5060), HOST_EXCEPTION_MSG);
}
TEST_CASE("jsip_uri basic (no params) , (no headers) , missing user , password given - (throw exception) ")
{
    REQUIRE_THROWS_WITH(jsip_uri(false , "voip.digicelgroup.com","","password",5060), PASSWORD_WITH_NO_USER_EXCEPTION_MSG);
}
TEST_CASE("jsip_uri compare (sucess)")
{
    auto sip_uri  = jsip_uri(false , "voip.digicelgroup.com","user","password",0);
    auto sips_uri  = jsip_uri(true , "voip.digicelgroup.com","user","password",0);
    REQUIRE(!(sips_uri == sip_uri));

    auto sip_uri_user_info_lowercase  = jsip_uri(false , "voip.digicelgroup.com","user","password",0);
    auto sip_uri_user_info_mixedcase  = jsip_uri(false , "voip.digicelgroup.com","USER","paSswOrd",0);
    REQUIRE(!(sip_uri_user_info_lowercase == sip_uri_user_info_mixedcase));

    auto sip_uri_host_info_lowercase  = jsip_uri(false , "voip.digicelgroup.com","user","password",0);
    auto sip_uri_host_info_uppercase  = jsip_uri(false , "voip.DIGICELGROUP.com","user","password",0);
    REQUIRE((sip_uri_host_info_lowercase == sip_uri_host_info_uppercase));

    auto sip_uri_no_port = jsip_uri(false , "voip.digicelgroup.com","user","password",0);
    auto sip_uri_port = jsip_uri(false , "voip.digicelgroup.com","user","password",5060);
    REQUIRE(!(sip_uri_no_port == sip_uri_port));
}