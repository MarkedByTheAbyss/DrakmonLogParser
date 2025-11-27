cmake_minimum_required(VERSION 3.10)
project(LogParser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(inc)

set(SOURCES
    src/parser-controller.cpp
    src/cli-config.cpp
    src/drakmon-log-parser.cpp
    src/functions.cpp
    src/main.cpp
    src/process-tree.cpp
    src/process-info.cpp
    src/yara-analyzer.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/lib/libyara64.lib)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /EHsc)
else()
    find_library(YARA_LIB yara REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${YARA_LIB})
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)