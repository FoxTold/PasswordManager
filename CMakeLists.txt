cmake_minimum_required(VERSION 3.10)
cmake_policy(VERSION 3.10)
set_property( GLOBAL PROPERTY USE_FOLDERS ON)
project(PasswordManager VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


set(SQLITECPP_BUILD_EXAMPLES OFF)
set(SQLITECPP_BUILD_TESTS OFF)

add_subdirectory(deps)
add_subdirectory(secpass)
add_subdirectory(samples)
