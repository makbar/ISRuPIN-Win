#include "utils/stdint.h"
#include "utils/byteorder.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "image.h"
#include "key.h"

Image::Image(unsigned long low_addr, unsigned long high_addr)
{
	this->low_addr = low_addr;
	this->high_addr = high_addr;
	this->key = NULL;
}

Image::~Image(void)
{
	if (this->key)
		delete this->key;
}

void Image::SetKey(const void *key_data, size_t len)
{
	switch (len) {
	case 2:
		this->key = new XOR16Key(key_data);
		break;
	case 32:
		this->key = new Transposition256Key(key_data);
		break;
	}
}

void Image::SetKey(const Key *key)
{
	switch (key->key_size) {
	case 2:
		this->key = new XOR16Key((XOR16Key *)key);
		break;
	case 32:
		this->key = new Transposition256Key((Transposition256Key *)key);
		break;
	}
}

uint16_t Image::Decode(uint16_t data)
{
	if (this->key)
		return this->key->Decode(data);
	else
		return data;
}
