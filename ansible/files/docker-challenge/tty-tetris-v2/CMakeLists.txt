cmake_minimum_required(VERSION 3.25)

PROJECT(tty-tetris)

OPTION(HOST_DEBUG "Enable debug build" OFF)
OPTION(USE_STDOUT_FOR_IO_CON "Use simplified console output functions" OFF)
OPTION(USE_SNPRINTF_FOR_IO_CON "Use stdlib snprintf instead of own version" OFF)

ADD_DEFINITIONS(-pipe --std=gnu99 -ftabstop=4 -Wno-unused-function)
ADD_DEFINITIONS(-Wall -Wmissing-declarations -Winit-self -Wswitch-enum -Wundef -Wshadow)
ADD_DEFINITIONS(-Wmissing-field-initializers -Wconversion -Wredundant-decls -Wpointer-arith)


IF (USE_STDOUT_FOR_IO_CON)
    ADD_DEFINITIONS(-DUSE_STDOUT_FOR_IO_CON)
ENDIF ()

IF (USE_SNPRINTF_FOR_IO_CON)
    ADD_DEFINITIONS(-DUSE_SNPRINTF_FOR_IO_CON)
ENDIF ()

FILE(GLOB SOURCES *.c nano/*.c)

ADD_EXECUTABLE(tty-tetris ${SOURCES})
target_link_libraries(tty-tetris curl)

IF (HOST_DEBUG)
    ADD_DEFINITIONS(-O0 -g3)
ELSE ()
    ADD_DEFINITIONS(-Os -Werror -fvisibility=hidden -ffast-math -fmerge-all-constants -ffunction-sections -fdata-sections)
ENDIF ()


INSTALL(TARGETS tty-tetris
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
)
