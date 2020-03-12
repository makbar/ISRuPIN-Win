#ifndef IMAGE_H
#define IMAGE_H

//#include <string>
//#include "Key.h"

class Key;

class Image {
public:
	unsigned long low_addr;
	unsigned long high_addr;
	Key *key;
	//std::string desc;

	Image(unsigned long low_addr, unsigned long high_addr);
	~Image(void);

	void SetKey(const void *key_data, size_t len);
	void SetKey(const Key *key);
	uint16_t Decode(uint16_t data);

	static bool CheckKeySize(int len) {
		return (len == 2 || len == 32);
	}

	bool IsEncrypted(void) {
		return (key!=NULL);
	}

};

#endif
