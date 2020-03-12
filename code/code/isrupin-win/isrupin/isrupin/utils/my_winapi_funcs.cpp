#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

#include "my_winapi_funcs.h"

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

int FindInSharedModules( DWORD processID, DWORD addr,
							void (*callback)(const char *modname, DWORD mod_low_addr, DWORD mod_high_addr) )
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	TCHAR szModName[MAX_PATH];
	MODULEINFO modinfo;
	DWORD low_addr, high_addr;

	// Get a handle to the process.
	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
							PROCESS_VM_READ,
							FALSE, processID );
	if (NULL == hProcess)
		return 1;

   // Get a list of all the modules in this process.

	if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
		{
			// Get the full path to the module's file.

			if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,
									  sizeof(szModName) / sizeof(TCHAR)))
			{
				if( GetModuleInformation(hProcess, hMods[i], &modinfo, sizeof(MODULEINFO)) )
				{
					low_addr = (DWORD) ((&modinfo)->lpBaseOfDll);
					high_addr = low_addr - 1 + ((&modinfo)->SizeOfImage);
					if (addr >= low_addr && addr <= high_addr) {
						// Found. Release the handle to the process. Return the address.
						callback((const char *)szModName, low_addr, high_addr);
						CloseHandle( hProcess );
						return 1;
					}
				}
			}
		}
	}

	// Not found. Release the handle to the process.
	CloseHandle( hProcess );
	return 0;
}

void ProcessMemoryMap( DWORD processID,
						void (*callback)(DWORD low_addr, DWORD size) )
{
	SYSTEM_INFO si;
	MEMORY_BASIC_INFORMATION memInfo;
	LPVOID lpAddress;
	HANDLE hProcess;

	// Get a handle to the process.
	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
							PROCESS_VM_READ,
							FALSE, processID );

	if (NULL == hProcess)
		return;

	GetSystemInfo(&si);

	lpAddress = si.lpMinimumApplicationAddress;
	while (  lpAddress < si.lpMaximumApplicationAddress )
	{
		if (VirtualQueryEx(hProcess, lpAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION))
			&& memInfo.State != MEM_FREE)
		{
			//printf("Base=%08X\tSize=%06X\tType=%03X\tState=%01X\n",
			//	memInfo.BaseAddress, memInfo.RegionSize, memInfo.Type>>16, memInfo.State>>12);
			callback((DWORD)(memInfo.BaseAddress), (DWORD)(memInfo.RegionSize));
			lpAddress = (LPVOID)((DWORD)(memInfo.BaseAddress) + (DWORD)(memInfo.RegionSize));
			continue;
		}
		lpAddress = (LPVOID)((DWORD)lpAddress + (DWORD)(si.dwPageSize));
	}

	CloseHandle( hProcess );
}

int GetHeapInfo(PVOID HeapHandle, PVOID *base, DWORD *size)
{
	PROCESS_HEAP_ENTRY h;

	if (base == NULL || size == NULL)
		return 0;

	if (!HeapWalk(HeapHandle, &h))
		return 0;

	*base = h.lpData;
	*size = h.cbData;
	return 1;
}
