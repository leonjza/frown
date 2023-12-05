cmake_minimum_required(VERSION 3.25)
project(ttyris C)

set(CMAKE_C_STANDARD 11)

add_library(ttyris SHARED library.c)

ADD_DEFINITIONS(-pipe --std=gnu99 -ftabstop=4 -Wno-unused-function)
ADD_DEFINITIONS(-Wall -Wmissing-declarations -Winit-self -Wswitch-enum -Wundef -Wshadow)
ADD_DEFINITIONS(-Wmissing-field-initializers -Wconversion -Wredundant-decls -Wpointer-arith)
ADD_DEFINITIONS(-Os -Werror -ffast-math -fmerge-all-constants -ffunction-sections -fdata-sections)
