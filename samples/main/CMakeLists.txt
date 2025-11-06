cmake_minimum_required(VERSION 3.10)
project(PasswordManager VERSION 1.0)

add_executable(main src/main.cpp)

target_link_libraries(main PRIVATE secpass)
