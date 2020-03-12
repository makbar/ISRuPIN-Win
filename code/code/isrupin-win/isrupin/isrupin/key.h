#ifndef KEY_H
#define KEY_H

extern "C" {
#include "utils/stdint.h"
#include "utils/byteorder.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}

class Key {
public:
	size_t key_size;

	virtual uint16_t Decode(uint16_t data) { return 0xbeef; }
};

class XOR16Key : public Key {
public:
	XOR16Key(const void *key);
	XOR16Key(const XOR16Key *key);
	uint16_t Decode(uint16_t data);

protected:
	uint16_t key;
};

class Transposition256Key : public Key {
public:
	Transposition256Key(const void *data);
	Transposition256Key(const Transposition256Key *key);
	uint16_t Decode(uint16_t data);

protected:
	uint16_t key[16];
};

#endif
