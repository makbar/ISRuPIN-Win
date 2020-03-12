#include "key.h"

XOR16Key::XOR16Key(const void *key)
{
	key_size = 2;
	// We need to byteswap here if we are on little endian
	this->key = htobe16(*(uint16_t *)key);
}

XOR16Key::XOR16Key(const XOR16Key *key)
{
	key_size = 2;
	this->key = key->key;
}

inline uint16_t XOR16Key::Decode(uint16_t data)
{
	return (data ^ this->key);
}

Transposition256Key::Transposition256Key(const void *key)
{
	int i, j;
	uint16_t bit1, bit2;

	key_size = 32;

	for (j = 0; j < 16; j++) {
		// We need to byteswap here if we are on little endian
		this->key[j] = htobe16(*((uint16_t *)key + j));
		uint16_t n = this->key[j];
		int bits = 0;
		while (n) {
			bits += n & 1;
			n >>= 1;
		}
		if (bits != 1) {
			printf("Row %d does not have 1 bit %d\n", j, bits);
			exit(1);
		}
	}

	// Create decryption matrix
	for (i = 0; i < 16; i++) {
		for (j = i + 1; j < 16; j++) {
			// bit1 = i,j
			bit1 = (this->key[i] >> j) & 0x01;
			// bit2 = j,i
			bit2 = (this->key[j] >> i) & 0x01;

			// Exchange
			this->key[j] &= ~(0x01 << i);
			this->key[j] |= bit1 << i;

			this->key[i] &= ~(0x01 << j);
			this->key[i] |= bit2 << j;
		}
	}
}

Transposition256Key::Transposition256Key(const Transposition256Key *key)
{
	key_size = 32;
	memcpy(this->key, key->key, 32);
}

inline uint16_t Transposition256Key::Decode(uint16_t data)
{
	int i;
	uint16_t bit, edata = 0;

	for (i = 0; i < 16; i++) {
		bit = (this->key[i] & data) != 0;
		edata |= bit << i;
	}

	return edata;
}
