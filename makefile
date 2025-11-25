# Compiler
CXX := g++
# Compiler flags
CXXFLAGS := -Iinc -Wall -Wextra -std=c++20 
#Flag for debugging -g
LDFLAGS := -Llib -lyara
# Sources and object files
SRC_DIR := src
OBJ_DIR := obj

SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

# Executable name
TARGET := LogParser

# default targets
all: $(TARGET)

# Rules for executable
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)

# Rules for object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Create dir for object files
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean object files and executable

clean:
	rm -rf $(OBJ_DIR) $(TARGET)
