CXX = g++
CC = gcc
CXXFLAGS = -Wall -Wextra -std=c++17 -O2 -fPIC -Iexternals -Iexternals/argon2/include -Iexternals/libsodium/src/libsodium/include
CFLAGS = -O2 -fPIC -Iexternals/argon2/include

TARGET_SO = pam_milipam.so
TARGET_BIN = milipam

SRC_SO = src/main.cpp
OBJ_SO = src/main.o

SRC_BIN = src/milipam.cpp
OBJ_BIN = src/milipam.o

JSON_URL = https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp
ARGON2_REPO = https://github.com/p-h-c/phc-winner-argon2.git
SODIUM_REPO = https://github.com/jedisct1/libsodium.git

ARGON2_LIB = externals/argon2/libargon2.a
ARGON2_HEADER = externals/argon2/include/argon2.h
SODIUM_LIB = externals/libsodium/src/libsodium/.libs/libsodium.a
SODIUM_HEADER = externals/libsodium/src/libsodium/include/sodium.h

all: $(TARGET_SO) $(TARGET_BIN)

externals/nlohmann/json.hpp:
	mkdir -p externals/nlohmann
	curl -sSL $(JSON_URL) -o externals/nlohmann/json.hpp

$(ARGON2_LIB) $(ARGON2_HEADER):
	mkdir -p externals
	git clone --depth 1 $(ARGON2_REPO) externals/argon2
	$(MAKE) -C externals/argon2 libargon2.a CC="$(CC)" CFLAGS="-O2 -fPIC -Iinclude"

$(SODIUM_LIB) $(SODIUM_HEADER):
	mkdir -p externals
	git clone --depth 1 -b stable $(SODIUM_REPO) externals/libsodium
	cd externals/libsodium && ./autogen.sh && ./configure CFLAGS="-O2 -fPIC" --disable-shared --enable-static --with-pic && $(MAKE) -j$$(nproc)

$(OBJ_SO): $(SRC_SO) externals/nlohmann/json.hpp $(ARGON2_HEADER) $(SODIUM_HEADER)
	$(CXX) $(CXXFLAGS) -c $(SRC_SO) -o $(OBJ_SO)

$(OBJ_BIN): $(SRC_BIN) externals/nlohmann/json.hpp $(ARGON2_HEADER) $(SODIUM_HEADER)
	$(CXX) $(CXXFLAGS) -c $(SRC_BIN) -o $(OBJ_BIN)

$(TARGET_SO): $(OBJ_SO) $(ARGON2_LIB) $(SODIUM_LIB)
	$(CXX) -shared -o $(TARGET_SO) $(OBJ_SO) $(ARGON2_LIB) $(SODIUM_LIB) -Wl,--allow-multiple-definition -lpam -pthread

$(TARGET_BIN): $(OBJ_BIN) $(ARGON2_LIB) $(SODIUM_LIB)
	$(CXX) $(CXXFLAGS) -o $(TARGET_BIN) $(OBJ_BIN) $(ARGON2_LIB) $(SODIUM_LIB) -Wl,--allow-multiple-definition -pthread

clean:
	rm -f $(OBJ_SO) $(OBJ_BIN) $(TARGET_SO) $(TARGET_BIN)

clean-all: clean
	rm -rf externals

.PHONY: all clean clean-all