#define CATCH_CONFIG_MAIN

#include "catch.hpp"
#include "../include/jsip_types.h"

TEST_CASE("convert_to_escaped_string password test (sucess)")
{
    REQUIRE(convert_to_escaped_string("2465300009",URI_USER_RESERVED_SET) == "2465300009");
    REQUIRE(convert_to_escaped_string("246?:@5&3@00009",URI_USER_RESERVED_SET) == "246?%3a%405&3%4000009");
    REQUIRE(convert_to_escaped_string("password",URI_PASS_RESERVED_SET) == "password");
    REQUIRE(convert_to_escaped_string("p@ss;wo/rd?:",URI_PASS_RESERVED_SET) == "p%40ss%3bwo%2frd%3f%3a");
}