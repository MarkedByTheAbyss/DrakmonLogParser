# Makefile for drakmonLogParser project on Ubuntu 22.04

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O2 -Iinc -I.

# Sources and headers
SRCS = \
    ArgParser.cpp \
    drakmonLogParser.cpp \
    functions.cpp \
    main.cpp \
    ProcessTree.cpp \
    YaraAnalyzer.cpp

OBJS = $(SRCS:.cpp=.o)

# Output binary
TARGET = drakmonLogParser

# YARA library (assumed installed system-wide)
LDFLAGS = -lyara

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)