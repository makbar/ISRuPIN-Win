#ifndef REPLACE_MEM_FUNCS_2
#define REPLACE_MEM_FUNCS_2

	PIN_InitSymbols();
	// Mark all loaded images, except the pintool, as accessible
	if (IMG_Name(img).find("isrupin.dll") == string::npos) {
		mp_set(imglow, imghigh - imglow, 0);
	}
/*
	if (IMG_Name(img).find("kernel32.dll") != string::npos) {
		RTN rtnVirtualAlloc, rtnVirtualFree;
		RTN rtnVirtualAllocEx, rtnVirtualFreeEx;
		rtnVirtualAlloc = RTN_FindByName(img, "VirtualAlloc");
		rtnVirtualFree = RTN_FindByName(img, "VirtualFree");
		rtnVirtualAllocEx = RTN_FindByName(img, "VirtualAllocEx");
		rtnVirtualFreeEx = RTN_FindByName(img, "VirtualFreeEx");
		if (RTN_Valid(rtnVirtualAlloc) && RTN_Valid(rtnVirtualFree)
			&& RTN_Valid(rtnVirtualAllocEx) && RTN_Valid(rtnVirtualFreeEx)) {
#ifdef maa2206_DEBUG
			stringstream sstr;
			sstr << "Found VirtualAlloc and VirtualFree in kernel32.dll. Replacing them." << endl;
			sstr << "Found VirtualAllocEx and VirtualFreeEx in kernel32.dll. Replacing them." << endl;
			OUTLOG(sstr);
#endif
			PROTO protoVirtualAlloc = PROTO_Allocate(PIN_PARG(LPVOID),
						CALLINGSTD_STDCALL, "VirtualAlloc",
						PIN_PARG(LPVOID), PIN_PARG(SIZE_T), PIN_PARG(DWORD),
						PIN_PARG(DWORD), PIN_PARG_END());
			PROTO protoVirtualFree = PROTO_Allocate(PIN_PARG(BOOL),
						CALLINGSTD_STDCALL, "VirtualFree", PIN_PARG(LPVOID),
						PIN_PARG(SIZE_T), PIN_PARG(DWORD), PIN_PARG_END());
			PROTO protoVirtualAllocEx = PROTO_Allocate(PIN_PARG(LPVOID),
						CALLINGSTD_STDCALL, "VirtualAllocEx",
						PIN_PARG(HANDLE), PIN_PARG(LPVOID),
						PIN_PARG(DWORD), PIN_PARG(DWORD),
						PIN_PARG(DWORD), PIN_PARG_END());
			PROTO protoVirtualFreeEx = PROTO_Allocate(PIN_PARG(BOOL),
						CALLINGSTD_STDCALL, "VirtualFreeEx",
						PIN_PARG(HANDLE), PIN_PARG(LPVOID),
						PIN_PARG(DWORD), PIN_PARG(DWORD), PIN_PARG_END());
			RTN_ReplaceSignature(rtnVirtualAlloc,
                         AFUNPTR(ReplacedVirtualAlloc),
                         IARG_PROTOTYPE, protoVirtualAlloc,
                         IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                         IARG_END);
			RTN_ReplaceSignature(rtnVirtualFree,
                         AFUNPTR(ReplacedVirtualFree),
                         IARG_PROTOTYPE, protoVirtualFree,
                         IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                         IARG_END);
			RTN_ReplaceSignature(rtnVirtualAllocEx,
                         AFUNPTR(ReplacedVirtualAllocEx),
                         IARG_PROTOTYPE, protoVirtualAllocEx,
                         IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                         IARG_END);
			RTN_ReplaceSignature(rtnVirtualFreeEx,
                         AFUNPTR(ReplacedVirtualFreeEx),
                         IARG_PROTOTYPE, protoVirtualFreeEx,
                         IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                         IARG_END);
			PROTO_Free(protoVirtualAlloc);
			PROTO_Free(protoVirtualFree);
			PROTO_Free(protoVirtualAllocEx);
			PROTO_Free(protoVirtualFreeEx);
		}
	}
	else if (IMG_Name(img).find("ntdll.dll") != string::npos) {
		RTN rtnHeapCreate, rtnHeapDestroy;
		rtnHeapCreate = RTN_FindByName(img, "RtlCreateHeap");
		rtnHeapDestroy = RTN_FindByName(img, "RtlDestroyHeap");
		if (RTN_Valid(rtnHeapCreate) && RTN_Valid(rtnHeapDestroy)) {
#ifdef maa2206_DEBUG
			sstr << "Found HeapCreate (RtlCreateHeap) and HeapDestroy (RtlDestroyHeap) in ntdll.dll. Replacing them." << endl;
			OUTLOG(sstr);
#endif
			PROTO protoHeapCreate = PROTO_Allocate(PIN_PARG(PVOID),
						CALLINGSTD_STDCALL, "RtlCreateHeap",
						PIN_PARG(ULONG), PIN_PARG(PVOID),
						PIN_PARG(SIZE_T), PIN_PARG(SIZE_T),	PIN_PARG(PVOID),
						PIN_PARG(PRTL_HEAP_PARAMETERS), PIN_PARG_END());
			PROTO protoHeapDestroy = PROTO_Allocate(PIN_PARG(PVOID),
						CALLINGSTD_STDCALL, "RtlDestroyHeap",
						PIN_PARG(PVOID), PIN_PARG_END());
			RTN_ReplaceSignature(rtnHeapCreate,
                         AFUNPTR(ReplacedHeapCreate),
                         IARG_PROTOTYPE, protoHeapCreate,
                         IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                         IARG_END);
			RTN_ReplaceSignature(rtnHeapDestroy,
                         AFUNPTR(ReplacedHeapDestroy),
                         IARG_PROTOTYPE, protoHeapDestroy,
                         IARG_THREAD_ID, IARG_CONTEXT, IARG_ORIG_FUNCPTR,
                         IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                         IARG_END);
			PROTO_Free(protoHeapCreate);
			PROTO_Free(protoHeapDestroy);
		}
	}
*/
#endif /* REPLACE_MEM_FUNCS_2 */
