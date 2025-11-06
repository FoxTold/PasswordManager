cmake_minimum_required(VERSION 3.10)
project(PasswordManager VERSION 1.0)

add_library(secpass 
    src/Database.cpp
    include/secpass/Database.hpp
)
target_include_directories(secpass PUBLIC include)

target_link_libraries(secpass 
    PRIVATE     SQLiteCpp
                sqlite3
                cryptopp::cryptopp)
