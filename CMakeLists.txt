# Минимальная версия CMake
cmake_minimum_required(VERSION 3.10)

# Имя проекта и язык
project(MyApp LANGUAGES CXX)

# Уровень стандарта C++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Добавляем заголовочные файлы
include_directories(inc)

# Источники
set(SOURCES
    src/ArgParser.cpp
    src/drakmonLogParser.cpp
    src/functions.cpp
    src/main.cpp
    src/ProcessTree.cpp
    src/YaraAnalyzer.cpp
)

# Создаём исполняемый файл
add_executable(app ${SOURCES})

# Добавляем зависимости для платформ
if(WIN32)
    # Windows-specific settings
    target_link_libraries(app PRIVATE ${CMAKE_SOURCE_DIR}/lib/libyara64.lib)
    # Можно добавить доп. флаги компилятора (аналог /W4 /EHsc)
    target_compile_options(app PRIVATE /W4 /EHsc)
else()
    # Unix-specific settings
    find_library(YARA_LIB yara REQUIRED)
    target_link_libraries(app PRIVATE ${YARA_LIB})
    # Например, для GCC/Clang
    target_compile_options(app PRIVATE -Wall -Wextra -pedantic)
endif()