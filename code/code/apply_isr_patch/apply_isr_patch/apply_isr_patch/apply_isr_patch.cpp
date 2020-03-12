/**
 * Muhammad Ali Akbar
 * maa2206@columbia.edu
 * Columbia University, NY
 *
 * For queries: ali.akbar.ceme@gmail.com
 *
 */

#include <iostream>
#include <fstream>
#include <cassert>
#include <windows.h>

using namespace std;

#define LINE_SIZE 1024

#define nonfatal_assert(x) \
	if (!(x)) { \
		printf("Error: Memory check assertion failed.\n"); \
		return -1; \
	}

DWORD image_base;
WORD nr_sections;
IMAGE_SECTION_HEADER *sec_head;

int seg_size;

int parse_PE(char *file, int size)
{
	int pos;
	IMAGE_DOS_HEADER *dos_head;
	IMAGE_NT_HEADERS *nt_head;
	if (!file || size <= 0) {
		printf("Invalid parameters.\n");
		return -1;
	}

	pos = 0;

	// Checking Signature
	dos_head = (IMAGE_DOS_HEADER *) (file + pos);
	pos += sizeof(*dos_head);
	nonfatal_assert(pos < size);
	if (dos_head->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("DOS header Signature check failed.\n");
		return -1;
	}

	pos = dos_head->e_lfanew;
	nonfatal_assert(pos < size);

	nt_head = (IMAGE_NT_HEADERS *) (file + pos);
	pos += sizeof(*nt_head);
	nonfatal_assert(pos < size);
	if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
		printf("NT header Signature check failed.\n");
		return -1;
	}

	image_base = nt_head->OptionalHeader.ImageBase;
	nr_sections = nt_head->FileHeader.NumberOfSections;
	sec_head = (IMAGE_SECTION_HEADER *) (file + pos);

	pos += nr_sections * sizeof(*sec_head);
	nonfatal_assert(pos <= size);

	return 0;
}

void print_sections()
{
	int i;
	IMAGE_SECTION_HEADER *sec;

	for (i = 0; i < nr_sections; i++) {
		sec = sec_head + i;
		printf("Section: %s (%d: %d) %d\n",
					sec->Name, image_base + sec->VirtualAddress,
					sec->PointerToRawData, sec->SizeOfRawData);
	}
}

int offset_in_file(int seg_base)
{
	int i;
	IMAGE_SECTION_HEADER *sec;

	for (i = 0; i < nr_sections; i++) {
		sec = sec_head + i;
		if (image_base + sec->VirtualAddress == seg_base) {
			seg_size = sec->SizeOfRawData;
			return sec->PointerToRawData;
		}
	}
	return -1;
}

int main(int argc, char *argv[])
{
	ifstream patch_file;
	ifstream in_file;
	ofstream out_file;
	int key;
	
	char *key_str;
	char *in_name;
	char *out_name;
	char *patch_name;

	char *buffer;
	char *patch_buffer;
	int size;

	int i, line_no;
	unsigned long temp;
	char * end;

	int last_seg_base, seg_base;
	int func_start, func_end;
	int offset, addr;
	char xor_char;

	key = 0;

	if (argc != 5) {
		printf("Usage: %s xor_encryption_key input_executable output_executable patch_file\n", argv[0]);
		return -1;
	}

	key_str = argv[1];
	in_name = argv[2];
	out_name = argv[3];
	patch_name = argv[4];

	temp = strtoul(key_str, &end, 16);
	key = (int) temp;
	if (!temp || key > 0xFFFF) {
		printf("Failed to parse key. It must be a valid hexadecimal number, non-zero and 2 bytes.\n");
		return -1;
	}
	//printf("Key: 0x%04x\n", key);

	in_file.open(in_name, ios::binary);
	if (!in_file.good()) {
		printf("Failed to open %s.\n", in_name);
		return -1;
	}

	out_file.open(out_name, ios::binary);
	if (!out_file.good()) {
		printf("Failed to open %s.\n", out_name);
		in_file.close();
		return -1;
	}

	patch_file.open(patch_name);
	if (!patch_file.good()) {
		printf("Failed to open %s.\n", patch_name);
		in_file.close();
		out_file.close();
		return -1;
	}

	in_file.seekg(0, ios::end);
	size = in_file.tellg();
	in_file.seekg(0, ios::beg);

	buffer = new char [2 * size];
	if (!buffer) {
		printf("Error: Not enough memory.\n");
		in_file.close();
		out_file.close();
		patch_file.close();
		return -1;
	}
	patch_buffer = buffer + size;
	for (i = 0; i < size; i++)
		patch_buffer[i] = 0;

	in_file.read(buffer, size);

	if (parse_PE(buffer, size) != 0) {
		printf("Error: Failed to parse PE Executable File (%s).\n", in_name);
		delete[] buffer;
		in_file.close();
		out_file.close();
		patch_file.close();
		return -1;
	}

	print_sections();

	line_no = 0;
	last_seg_base = -1;
	while (patch_file.good()) {
		line_no++;
		seg_base = -1;
		func_start = -1;
		func_end = -1;
		patch_file >> seg_base >> func_start >> func_end;
		if (seg_base < 0 || func_start < 0 || func_end < 0 ||
			func_start > func_end || func_end >= size)
			continue;

		printf("%d %d %d\n", seg_base, func_start, func_end);

		if (seg_base != last_seg_base) {
			offset = offset_in_file(seg_base);
			last_seg_base = seg_base;
		}

		if (offset < 0 || offset + func_end >= size) {
			printf("Patch File Line Number %d is Invalid!\n", line_no);
			delete[] buffer;
			in_file.close();
			out_file.close();
			patch_file.close();
			return -1;
		}

		for (i = func_start; i < func_end; i++) {
			addr = seg_base + i;
			if (addr & 0x00000001)
				xor_char = ((char *) &key) [1];
			else
				xor_char = ((char *) &key) [0];
			patch_buffer[offset + i] = xor_char;
		}
	}

	for (i = 0; i < size; i++) {
		buffer[i] ^= patch_buffer[i];
	}

	out_file.write(buffer, size);

	delete[] buffer;
	in_file.close();
	out_file.close();
	patch_file.close();
	return 0;
}
