cmake_minimum_required(VERSION 3.10)
project(MalDev C)

set(CMAKE_C_STANDARD 99)

add_executable(main src/main.c)

# Ajoute les symboles de débogage
#target_compile_options(main PRIVATE -g)

# Strip le binaire
target_link_options(main PRIVATE -s)

# Link avec la librairie winhttp
target_link_libraries(main PRIVATE winhttp)
