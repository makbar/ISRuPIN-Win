#ifndef MY_WINAPI_FUNCS_H
#define MY_WINAPI_FUNCS_H

typedef void * PVOID;
typedef unsigned long ULONG;
typedef struct _RTL_HEAP_PARAMETERS * PRTL_HEAP_PARAMETERS;

typedef void * LPVOID;
typedef void * HANDLE;
typedef unsigned long DWORD;
typedef unsigned long SIZE_T;

int FindInSharedModules( DWORD processID, DWORD addr,
							void (*callback)(const char *modname, DWORD mod_low_addr, DWORD mod_high_addr) );

void ProcessMemoryMap( DWORD processID,
						void (*callback)(DWORD low_addr, DWORD size) );

int GetHeapInfo(PVOID HeapHandle, PVOID *base, DWORD *size);

#endif //MY_WINAPI_FUNCS_H
