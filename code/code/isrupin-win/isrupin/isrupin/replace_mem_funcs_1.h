#ifndef REPLACE_MEM_FUNCS_1
#define REPLACE_MEM_FUNCS_1

static LPVOID ReplacedVirtualAlloc(THREADID tid, CONTEXT *ctx, AFUNPTR f,
		LPVOID lpAddress, SIZE_T dwsize, DWORD flAllocationType, DWORD flProtect)
{
	LPVOID ret;
	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, f,
					PIN_PARG(LPVOID), &ret, PIN_PARG(LPVOID), lpAddress,
					PIN_PARG(SIZE_T), dwsize, PIN_PARG(DWORD), flAllocationType,
					PIN_PARG(DWORD), flProtect, PIN_PARG_END());
#ifdef maa2206_DEBUG
			stringstream sstr;
			sstr << "ReplacedVirtualAlloc(" << (void *)lpAddress << "," << dwsize << ") = " << (void *)ret << endl;
			OUTLOG(sstr);
#endif
	if (ret)
		mp_set((ADDRINT)ret, (ADDRINT)dwsize, 0);
	return ret;
}

static BOOL ReplacedVirtualFree(THREADID tid, CONTEXT *ctx, AFUNPTR f,
	LPVOID lpAddress, SIZE_T dwsize, DWORD dwFreeType)
{
	BOOL ret;
	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, f,
					PIN_PARG(BOOL), &ret, PIN_PARG(LPVOID), lpAddress,
					PIN_PARG(SIZE_T), dwsize, PIN_PARG(DWORD), dwFreeType,
					PIN_PARG_END());
#ifdef maa2206_DEBUG
			stringstream sstr;
			sstr << "ReplacedVirtualFree(" << (void *)lpAddress << "," << dwsize << ")" << endl;
			OUTLOG(sstr);
#endif
	if (ret)
		mp_set((ADDRINT)lpAddress, (ADDRINT)dwsize, 0xff);
	return ret;
}

static LPVOID ReplacedVirtualAllocEx(THREADID tid, CONTEXT *ctx, AFUNPTR f,
		HANDLE hProcess, LPVOID lpAddress, DWORD dwsize, DWORD flAllocationType, DWORD flProtect)
{
	LPVOID ret;
	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, f,
					PIN_PARG(LPVOID), &ret, 
					PIN_PARG(HANDLE), hProcess, PIN_PARG(LPVOID), lpAddress,
					PIN_PARG(DWORD), dwsize, PIN_PARG(DWORD), flAllocationType,
					PIN_PARG(DWORD), flProtect, PIN_PARG_END());
#ifdef maa2206_DEBUG
			stringstream sstr;
			sstr << "ReplacedVirtualAllocEx(" << (void *)lpAddress << "," << dwsize << ") = " << (void *)ret << endl;
			OUTLOG(sstr);
#endif
	if (ret)
		mp_set((ADDRINT)ret, (ADDRINT)dwsize, 0);
	return ret;
}

static BOOL ReplacedVirtualFreeEx(THREADID tid, CONTEXT *ctx, AFUNPTR f,
	HANDLE hProcess, LPVOID lpAddress, DWORD dwsize, DWORD dwFreeType)
{
	BOOL ret;
	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, f,
					PIN_PARG(BOOL), &ret,
					PIN_PARG(HANDLE), hProcess, PIN_PARG(LPVOID), lpAddress,
					PIN_PARG(DWORD), dwsize, PIN_PARG(DWORD), dwFreeType,
					PIN_PARG_END());
#ifdef maa2206_DEBUG
			stringstream sstr;
			sstr << "ReplacedVirtualFreeEx(" << (void *)lpAddress << "," << dwsize << ")" << endl;
			OUTLOG(sstr);
#endif
	if (ret)
		mp_set((ADDRINT)lpAddress, (ADDRINT)dwsize, 0xff);
	return ret;
}

static PVOID ReplacedHeapCreate(THREADID tid, CONTEXT *ctx, AFUNPTR f,
		ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize,
		SIZE_T CommitSize, PVOID Lock, PRTL_HEAP_PARAMETERS Parameters)
{
	PVOID ret;
	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, f,
					PIN_PARG(PVOID), &ret, PIN_PARG(ULONG), Flags,
					PIN_PARG(PVOID), HeapBase, PIN_PARG(SIZE_T), ReserveSize,
					PIN_PARG(SIZE_T), CommitSize, PIN_PARG(PVOID), Lock,
					PIN_PARG(PRTL_HEAP_PARAMETERS), Parameters,
					PIN_PARG_END());
#ifdef maa2206_DEBUG
			stringstream sstr;
			sstr << "ReplacedHeapCreate(" << (void *)HeapBase << ", " << ReserveSize << ", " << CommitSize << ") = " << (void *)ret << endl;
			OUTLOG(sstr);
#endif
		if (ret) {
			int size;
			switch (ReserveSize) {
				case 0:
					if (CommitSize == 0)
						size = 64 * PAGE_SIZE;
					else
						size = CommitSize;
					break;
				default:
					size = ReserveSize;
					break;
			}
			mp_set((ADDRINT)ret, (ADDRINT)size, 0);
		}

	return ret;
}

static PVOID ReplacedHeapDestroy(THREADID tid, CONTEXT *ctx, AFUNPTR f,
		PVOID HeapHandle)
{
	PVOID ret;

	PVOID base;
	DWORD size;
	int found;

	found = GetHeapInfo(HeapHandle, &base, &size);

	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, f,
					PIN_PARG(PVOID), &ret, PIN_PARG(PVOID), HeapHandle,
					PIN_PARG_END());
#ifdef maa2206_DEBUG
			stringstream sstr;
			sstr << "ReplacedHeapDestroy(" << (void *)HeapHandle << ") = " << (void *)ret << endl;
			OUTLOG(sstr);
#endif
	if (ret == NULL && found == 1)
		mp_set((ADDRINT)base, (ADDRINT)size, 0xff);

	return ret;
}

#endif /* REPLACE_MEM_FUNCS_1 */
