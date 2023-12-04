cmake_minimum_required(VERSION 3.25)
project(ttyris C)

set(CMAKE_C_STANDARD 11)

add_library(ttyris SHARED library.c)
