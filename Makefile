# DSign_server Linux 构建脚本
# 依赖：g++ (支持 C++17)、OpenSSL 开发库（openssl-devel / libssl-dev）、pthread
# 用法：make        生成 DSign_server
#       make clean  清理

CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -pthread

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

TARGET := DSign_server
SRC    := server.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) -o $@ $(SRC) $(OPENSSL_LIBS) -lpthread

clean:
	rm -f $(TARGET)

.PHONY: all clean
