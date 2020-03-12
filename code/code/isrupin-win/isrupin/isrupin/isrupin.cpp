#include <iostream>
#include <sstream>
#include <fstream>
#include <list>
#include <vector>
#include <cassert>
#include "pin.H"
#include "key.h"
#include "image.h"
#include "likely.h"
#include "utils/sortedvector.h"
#include "utils/win_unixlibfuncs.h"
#include "utils/my_winapi_funcs.h"

extern "C" {
#include "utils/sqlite3.h"
#include <time.h>
#include <signal.h>
}

#define maa2206_DEBUG//
#define SIGNAL_DEBUG//
#define UNKNOWN_DEBUG//
//#define UNKNOWN_DEBUG_ORIG
#define MP_DEBUG//
#define MP_PAUSE() do { ForceExit(-1); } while (0)
//#define MP_PAUSE() do { } while (0)
//#define MP_PAUSE() do { pause(); } while (0)//
#define DL_DEBUG//

#define PAGEOFF_MASK	(0xfff)
#define KERNEL_BOUNDARY 0x80000000UL		/* x86 */
//#define KERNEL_BOUNDARY 0x80000000000UL 	/* x86_64 */

#define ISOLATE_MEMORY//

// Map of loaded images
static list<Image *> image_list;
// Last loaded image (dummy cache)
static Image *last_fetch_img = NULL;
// A dummy image used to de-randomize with a randomly generate key
static Image *random_image = NULL;
// Running a signal handler (one signal per-process)
static BOOL sighandler = FALSE;
static string keydbfn;

// Last verified signal trampoline
static struct {
	ADDRINT low, high;
} tramp;

// XED is used for decoding unknown instructions
#ifdef UNKNOWN_DEBUG
extern "C" {
#include "xed-interface.h"
}

static xed_state_t dstate;
static BOOL do_disas = FALSE;
#endif

// Statistics
static UINT64 image_hits = 0;
static UINT64 fcallcount = 0;

// Log file
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "isr.log", "Specify output file name. PID is appended");

// Image keys DB
KNOB<string> KnobKeyDB(KNOB_MODE_WRITEONCE, "pintool", "keydb", "image_keys.db",
		 "Key database to use");

static ofstream OutFile;

static VOID ERRLOG(stringstream &sstr)
{
	if (OutFile)
		OutFile << sstr.str();
	LOG(sstr.str());
	cerr << sstr.str();
	sstr.str("");
}

#if 0
static VOID ERRLOG(string &s)
{
	LOG(s);
	cerr << s;
}
#endif

static VOID ERRLOG(const char *s)
{
	if (OutFile)
		OutFile << s;
	LOG(s);
	cerr << s;
}

static VOID OUTLOG(stringstream &sstr)
{
	if (OutFile)
		OutFile << sstr.str();
	LOG(sstr.str());
	sstr.str("");
}

#if 0
static VOID OUTLOG(string &s)
{
	LOG(s);
}
#endif

static VOID OUTLOG(const char *s)
{
	if (OutFile)
		OutFile << s;
	LOG(s);
}

static VOID ForceExit(INT32 code);

static sqlite3 *OpenDB()
{
	sqlite3 *db;

	if (sqlite3_open(KnobKeyDB.Value().c_str(), &db) != 0) {
		ERRLOG("SQLite error opening keys db\n");
		if (db) {
			ERRLOG(sqlite3_errmsg(db));
			sqlite3_close(db);
		}
		return NULL;
	}
	return db;
}

static BOOL GetImageKey(const char *path, Image *img)
{
	const void *key_p;
	int r, keylen;
	stringstream sstr;
	sqlite3_stmt *stmt;
	sqlite3 *db = NULL;
	const char *sqlstr = "SELECT image_key.key FROM image_key,image"
		" WHERE image.path=? AND image_key.keyid=image.keyid";

	if ((db = OpenDB()) == NULL)
		return FALSE;

	r = sqlite3_prepare_v2(db, sqlstr, -1, &stmt, NULL);
	if (r != SQLITE_OK) {
query_error:
		sstr << "SQLite error querying keys db: " << 
			sqlite3_errmsg(db) << endl;
		ERRLOG(sstr);
		sqlite3_close(db);
		return FALSE;
	}
	r = sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
	if (r != SQLITE_OK)
		goto query_error;

	r = sqlite3_step(stmt);
	if (r == SQLITE_ROW) {
		keylen = sqlite3_column_bytes(stmt, 0);
		key_p = sqlite3_column_blob(stmt, 0);

		if (!Image::CheckKeySize(keylen)) {
			sstr << "ERROR: Invalid key size " << keylen << endl;
			ERRLOG(sstr);
			goto ret;
		}

		img->SetKey(key_p, keylen);
		//OutFile << "Key found and set to " << (void *)img->key << endl;
	} else if (r == SQLITE_DONE) {
#if 1
		OutFile << "NOTICE: No key found for " << path <<
			". Assuming file is not encrypted." << endl;
#endif
	} else
		goto query_error;

ret:
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return TRUE;
}

// Create new image and add it in the image map
static VOID AddExecutableImage(const string &name, ADDRINT low, ADDRINT high)
{
	stringstream sstr;
	Image *img_entry;

	img_entry = new Image(low, high);
	if (!GetImageKey(name.c_str(), img_entry))
		ForceExit(1);

	// Page align low and high addresses
	if (low & PAGEOFF_MASK) 
		low &= ~PAGEOFF_MASK;
	if (high & PAGEOFF_MASK)
		high |= PAGEOFF_MASK;

	image_list.push_front(img_entry);

	sstr << "Adding image " << name << ' ' << 
		(void *)low << '-' << (void *)high;
	if (img_entry->IsEncrypted())
		sstr << " E" << endl;
	else
		sstr << "  " << endl;
	OUTLOG(sstr);
}

static inline BOOL TryDeleteImage(Image *img, ADDRINT low, ADDRINT high)
{
	// Image:              |--------------|
	// Delete case 1:   |--------|
	// Delete case 2:               |---------|
	// Delete case 3:          |----|
	// Delete case 4:   |----------------------|
	
	if (low <= img->low_addr && high >= img->low_addr) {
		// Case 1 & 4. Low addr of image in delete segment
		img->low_addr = high;
	} else if (low <= img->high_addr && high >= img->high_addr) {
		// Case 2 & 4. High addr of image in delete segment
		img->high_addr = low;
	} else if (low > img->low_addr && high < img->low_addr) {
		// Case 3. Delete segment within image. Requires splitting
		// Create another image for the second part
		Image *newimg = new Image(high, img->high_addr);
		newimg->SetKey(img->key);
		image_list.push_front(newimg);
		// Resizing first part of image
		img->high_addr = low;
		return FALSE;
	}

	// Check if image should be deleted
	if (img->low_addr >= img->high_addr)
		return TRUE;
	return FALSE;
}

static VOID DeleteImage(ADDRINT low, ADDRINT high)
{
	list<Image *>::iterator it;
	Image *img_entry;
	BOOL erase_entry;

	// Page align low and high addresses
	if (low & PAGEOFF_MASK) 
		low &= ~PAGEOFF_MASK;
	if (high & PAGEOFF_MASK)
		high |= PAGEOFF_MASK;

	for (it = image_list.begin(); it != image_list.end();) {
		img_entry = *it;
		erase_entry = TryDeleteImage(*it, low, high);
		if (erase_entry) {
			it = image_list.erase(it);
			delete img_entry;
		} else
			it++;
	}
}

/********************/
/* Memory Isolation */
/********************/
#ifdef ISOLATE_MEMORY

// 2 GB address space
#define PAGE_SIZE	4096
#define MEMPROTECTOR_SIZE	(KERNEL_BOUNDARY >> 12)
#define MEMPROTECTOR_MAXADDR	(KERNEL_BOUNDARY - 1)
#define VECTOR_BLOCK_SIZE 	16


typedef struct syscall_data_struct {
	ADDRINT sysnr;
	ADDRINT arg[6];
} syscall_data_t;

static UINT8 *memory_protector = NULL;
static ADDRINT heap_end = 0;
static vector<syscall_data_t> syscall_tracker;


static VOID mp_set(ADDRINT start, ADDRINT size, UINT8 val)
{
	ADDRINT stop;
#ifdef MP_DEBUG
	stringstream sstr;
#endif

	stop = start + size;
	if (stop & 0xfff)
		stop = (stop >> 12) + 1;
	else
		stop >>= 12;

	// Check that we don't attempt to protect kernel memory
	// E.g., the VDSO may reside in kernel space, but it's r-x only
        if (start >= KERNEL_BOUNDARY) {
#ifdef MP_DEBUG
                sstr << "Attempting to protect kernel memory " << (void *)start 
			<< '-' << (void *)(stop << 12) << endl;
		OUTLOG(sstr);
#endif
                return;
        }

#ifdef MP_DEBUG
	sstr << (VOID *)start << "-" << (VOID *)(stop << 12) << endl;
	OUTLOG(sstr);
#endif

	start >>= 12;
	while (start < stop)
		memory_protector[start++] = val;
}

#include "replace_mem_funcs_1.h"

static VOID ThreadCreate(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	if (syscall_tracker.capacity() <= tid) {
		syscall_tracker.reserve(tid + VECTOR_BLOCK_SIZE);
	}
}

static BOOL MemoryProtectorInit(void)
{
	memory_protector = (UINT8 *)mmap(0, MEMPROTECTOR_SIZE,
			PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (memory_protector == MAP_FAILED) {
		cerr << "Could not allocate memory protector" << endl;
		return FALSE;
	}
	memset(memory_protector, 0xff, MEMPROTECTOR_SIZE);

//	PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
//	PIN_AddSyscallExitFunction(SyscallExit, NULL);
//	PIN_AddThreadStartFunction(ThreadCreate, NULL);

	return TRUE;
}

void testinvalid_callback(DWORD low_addr, DWORD size)
{
	mp_set(low_addr, size, 0);
}

static VOID InvalidAccess(CONTEXT *ctx, THREADID tid, ADDRINT addr, UINT32 sz)
{
	stringstream sstr;
	EXCEPTION_INFO einfo;

#ifdef maa2206_DEBUG
	ProcessMemoryMap(PIN_GetPid(), testinvalid_callback);
#endif

	sstr << "WARNING: MP Exception at " << (void *)addr << 
		'(' << sz << ')' << endl;
	ERRLOG(sstr);
	MP_PAUSE();

	PIN_InitAccessFaultInfo(&einfo, EXCEPTCODE_ACCESS_DENIED,
			PIN_GetContextReg(ctx, REG_INST_PTR), addr,
			FAULTY_ACCESS_WRITE);
	PIN_RaiseException(ctx, tid, &einfo);
}

void ProcessMMaps();

static ADDRINT PIN_FAST_ANALYSIS_CALL CheckByteAccess(ADDRINT addr)
{
	UINT8 p = *(memory_protector + (addr >> 12));
#ifdef maa2206_DEBUG
	if (p)
		ProcessMMaps();
	p = *(memory_protector + (addr >> 12));
#endif
	return p;
//	return *(memory_protector + (addr >> 12));
}

static ADDRINT PIN_FAST_ANALYSIS_CALL CheckWordAccess(ADDRINT addr)
{
	UINT8 p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + 1) >> 12));
#ifdef maa2206_DEBUG
	if (p)
		ProcessMMaps();
	p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + 1) >> 12));
#endif
	return p;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL CheckDWordAccess(ADDRINT addr)
{
	UINT8 p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + 3) >> 12));
#ifdef maa2206_DEBUG
	if (p)
		ProcessMMaps();
	p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + 3) >> 12));
#endif
	return p;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL CheckQWordAccess(ADDRINT addr)
{
	UINT8 p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + 7) >> 12));
#ifdef maa2206_DEBUG
	if (p)
		ProcessMMaps();
	p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + 7) >> 12));
#endif
	return p;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL CheckDQWordAccess(ADDRINT addr)
{
	UINT8 p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + 15) >> 12));
#ifdef maa2206_DEBUG
	if (p)
		ProcessMMaps();
	p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + 15) >> 12));
#endif
	return p;
}

static ADDRINT PIN_FAST_ANALYSIS_CALL CheckNByteAccess(ADDRINT addr, UINT32 sz)
{
	UINT8 p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + sz - 1) >> 12));
#ifdef maa2206_DEBUG
	if (p)
		ProcessMMaps();
	p = *(memory_protector + ((UINT32)addr >> 12));
	p |= *(memory_protector + (((UINT32)addr + sz - 1) >> 12));
#endif
	return p;
}

#ifdef MP_DEBUG
static VOID PIN_FAST_ANALYSIS_CALL DebugAddress(VOID *addr, UINT32 sz)
{
	if (((UINT32)addr + sz - 1) > MEMPROTECTOR_MAXADDR) {
		stringstream sstr;

		sstr << "Invalid memory address " << addr <<
			"(" << sz << ")" << endl;
		OUTLOG(sstr);
	}
}
#endif

static inline VOID MemoryIsolate(INS ins, VOID *v)
{
	USIZE wsize;

	if (INS_IsMemoryWrite(ins) == FALSE)
		return;

#ifdef MP_DEBUG
	INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
			(AFUNPTR)DebugAddress,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_MEMORYWRITE_SIZE,
			IARG_END);
#endif

	switch ((wsize = INS_MemoryWriteSize(ins))) {
	case 1:
		INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE,
				(AFUNPTR)CheckByteAccess,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA, IARG_END);
		break;
	case 2:
		INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE,
				(AFUNPTR)CheckWordAccess,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA, IARG_END);
		break;
	case 4:
		INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE,
				(AFUNPTR)CheckDWordAccess,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA, IARG_END);
		break;
	case 8:
		INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE,
				(AFUNPTR)CheckQWordAccess,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA, IARG_END);
		break;
	case 16:
		INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE,
				(AFUNPTR)CheckDQWordAccess,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA, IARG_END);
		break;

	default:
		INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE,
				(AFUNPTR)CheckNByteAccess,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
				IARG_END);
		break;
	}

	INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)InvalidAccess,
			IARG_CONTEXT, IARG_THREAD_ID,
			IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
}
#endif /* ifdef ISOLATE_MEMORY */

#ifdef UNKNOWN_DEBUG
static VOID disas_ins(string *dis_str)
{
	stringstream sstr;

	sstr << "Running instruction " << dis_str->c_str() << endl;
	OUTLOG(sstr);
}
#endif

#if defined(ISOLATE_MEMORY) || defined(UNKNOWN_DEBUG)
static VOID InstrumentTrace(TRACE trace, VOID *v)
{
	BBL bbl;
	INS ins;
	string dis;

#ifdef UNKNOWN_DEBUG
	if (do_disas) {
		for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			for (ins = BBL_InsHead(bbl); INS_Valid(ins);
					ins = INS_Next(ins)) {
				dis = INS_Disassemble(ins);
				INS_InsertCall(ins, IPOINT_BEFORE,
						(AFUNPTR)disas_ins,
						IARG_PTR, new string(dis),
						IARG_END);
#ifdef ISOLATE_MEMORY
				MemoryIsolate(ins, v);
#endif
			}
		}
		return;
	}
#endif

#ifdef ISOLATE_MEMORY
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (ins = BBL_InsHead(bbl); INS_Valid(ins);
				ins = INS_Next(ins)) {
			MemoryIsolate(ins, v);
		}
	}
#endif
}
#endif

void mmaps_callback(DWORD low_addr, DWORD size)
{
#ifdef ISOLATE_MEMORY
	mp_set(low_addr, size, 0);
#endif
}

static void ProcessMMaps(void)
{
	ProcessMemoryMap(PIN_GetPid(), mmaps_callback);
}

static inline void dl_callback(const char* modname, DWORD low_addr, DWORD high_addr)
{
	AddExecutableImage(modname, low_addr, high_addr);
}

static inline Image *FindImageByAddr(ADDRINT addr)
{
	Image *img = NULL;
	BOOL trytoresolve = true;
	list<Image *>::iterator it;

retry:
	for (it = image_list.begin(); it != image_list.end(); it++) {
		img = *it;
		if (img->low_addr <= addr && addr <= img->high_addr)
			return img;
	}

	if (trytoresolve) {
		// Figure out the tool's address
#ifdef DL_DEBUG
		OUTLOG("Looking in loaded shared objects\n");
#endif
		trytoresolve = false;
		if (FindInSharedModules((DWORD) PIN_GetPid(), (DWORD) addr, dl_callback))
			goto retry;
	}

	return NULL;
}

static size_t FetchInstruction(void *buf, ADDRINT addr, size_t size,
        EXCEPTION_INFO *pExceptInfo, VOID *v)
{
	size_t copied, off, ext, effective_size;
	Image *img;
	UINT8 copy_buf[16];
	ADDRINT aligned_addr;
	UINT16 *start, *end;
	stringstream sstr;

	fcallcount++;

	// Check last used image first
	if (likely(last_fetch_img && last_fetch_img->low_addr <= addr &&
			addr <= last_fetch_img->high_addr)) {
		image_hits++;
		img = last_fetch_img;
	} else if ((img = FindImageByAddr(addr)) != NULL)
		last_fetch_img = img;

	// Quickly return unencrypted image data
	if (img && !img->IsEncrypted()) {
		effective_size = PIN_SafeCopyEx(buf, (UINT8 *)addr, 
				size, pExceptInfo);
			
/*		sstr << "Fetching from unencrypted image " <<
				(void *)addr << " bytes:" << size << endl;
		OUTLOG(sstr);
		sstr.flush();
*/
		goto just_ret;
	}

	// Align address and size
	off = ext = 0;
	if (addr & 0x01) {
		aligned_addr = addr & ~0x01;
		off = 1;
		size++;
	} else {
		aligned_addr = addr;
		if (size & 0x01) {
			ext = 1;
			size++;
		}
	}

	// Fetch data in temporary buffer
	copied = PIN_SafeCopyEx(copy_buf, (UINT8 *)aligned_addr,
			size, pExceptInfo);
	if (likely(copied == size))
		effective_size = copied - off - ext;
	else if (unlikely(copied <= off)) {
		effective_size = 0;
		goto just_ret;
	} else
		effective_size = copied - off;


	// Handle case of signal trampolines and reads of null bytes
	if (unlikely(img == NULL)) {
//		if (IsTrampoline(addr, copy_buf + off, effective_size))
//			goto ret;
//		else {
			img = random_image;

			// Image not found
			sstr << "WARNING: Fetching from unknown image " <<
				(void *)addr << " bytes:" << copied << " = " << off << ", " << ext << endl;
			OUTLOG(sstr);
			sstr.flush();

#ifdef UNKNOWN_DEBUG
			do_disas = TRUE;
			CODECACHE_FlushCache();
#ifdef UNKNOWN_DEBUG_ORIG
			char hbuf[copied * 2 + 1];


			for (size_t i = off; i < copied; i++)
				sprintf(hbuf + i*2, "%02x",
						(int)*((UINT8 *)copy_buf + i));
			hbuf[copied * 2] = '\0';
			sstr << "Decoding " << (void *)addr << "=" << 
				hbuf << endl;
			OUTLOG(sstr);
			sstr.str("");
			DecodeInstruction(addr, copy_buf + off, copied - off);
#endif
#endif
//		}

	} else {
/*			sstr << "Fetching from known image " <<
				(void *)addr << " bytes:" << copied << " = " << off << ", " << ext << endl;
			OUTLOG(sstr);
			sstr.flush();
*/	}

	// Decrypt instructions
	start = (UINT16 *)copy_buf;
	end = (UINT16 *)(copy_buf + copied);
	for (; start < end; start++) {
		//sstr << "Original " << (void *)aligned_addr << " " <<
		//	(void *)*start << endl;
		*start = img->Decode(*start);
		//sstr << "Decrypted " << (void *)*start << endl;
		//OUTLOG(sstr);
	}
	//dcount += copied;

//ret:
	memcpy(buf, copy_buf + off, effective_size);
just_ret:
	return effective_size;
}

/* Handle image loading */
static VOID LoadImage(IMG img, VOID *v)
{
	ADDRINT imglow, imghigh;
	imglow = IMG_LowAddress(img);
	imghigh = IMG_HighAddress(img);

	AddExecutableImage(IMG_Name(img), imglow, imghigh);

#ifdef maa2206_DEBUG
	stringstream sstr;
	sstr << "Loading Image: " << IMG_Name(img) << endl;
	OUTLOG(sstr);
#endif

#ifdef ISOLATE_MEMORY
#include "replace_mem_funcs_2.h"
#endif
}

static VOID UnloadImage(IMG img, VOID *v)
{
	list<Image *>::iterator it;
	stringstream sstr;
	ADDRINT low, high;
	
	low = IMG_LowAddress(img);
	high = IMG_HighAddress(img);
	sstr << "Unloading " << IMG_Name(img) << endl;
	OUTLOG(sstr);
	DeleteImage(low, high);
}

static BOOL FaultHandler(THREADID tid, INT32 sig, CONTEXT *ctx, 
		BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
	Image *img;
	string signame, exceptname;
	ADDRINT feip;
	stringstream sstr;
	unsigned char tmpbuf[1];
	
	//cerr << "Fault handler!!!!" << endl;

	switch (sig) {
	case SIGSEGV:
		signame = "SIGSEGV";
		break;
	case SIGFPE:
		signame = "SIGFPE";
		break;
	case SIGILL:
		signame = "SIGILL";
		break;
	case SIGABRT:
		signame = "SIGABRT";
		break;
	default:
		//signame = strsignal(sig);
//		sstr << "ERROR: Fault handler caught unexpected signal " 
//			<< sig << " " << signame << endl;
		sstr << "ERROR: Fault handler caught unexpected signal " 
			<< sig << endl;
		OUTLOG(sstr);
		break;
	}

	exceptname = PIN_ExceptionToString(pExceptInfo);
	feip = PIN_GetExceptionAddress(pExceptInfo);
	if (feip == 0) {
		feip = PIN_GetContextReg(ctx, REG_INST_PTR);
	}

	sstr << "ISRUPIN thread [" << tid << "] Received signal " << signame 
		<< " at " << (void *)feip << endl << exceptname << endl;
	ERRLOG(sstr);

	// Check last used image first
	if (last_fetch_img && last_fetch_img->low_addr <= feip &&
			feip <= last_fetch_img->high_addr) {
		img = last_fetch_img;
	} else {
		img = FindImageByAddr(feip);
	}

	if (img != NULL) {
		ERRLOG("WARNING: Fault in application image.\n");
		goto possible_ci;
	} else {
		ERRLOG("WARNING: Error occured in "
				"unknown/un-randomized code\n");

		if (PIN_SafeCopy(tmpbuf, (VOID *)feip, 1) < 1) {
			sstr << "WARNING: " << (VOID *)feip << 
				" inaccessible." << endl;
			ERRLOG(sstr);
possible_ci:
			sstr << "WARNING: Small chance of code-injection." 
				<< endl << 
				"WARNING: Check that unknown code was fetched."
				<< endl;
			ERRLOG(sstr);
		} else {
			sstr << "WARNING: " << (VOID *)feip << " inaccessible."
				<< endl << 
				"ISRUPIN: High-possibility of code-injection." 
				<< endl << 
				"ISRUPIN: Check that unknown code was fetched."
				<< endl;
			ERRLOG(sstr);
		}
	}
	return TRUE;
}

static VOID ContextSwitch(THREADID threadIndex, CONTEXT_CHANGE_REASON reason,
		const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v) 
{
#ifdef SIGNAL_DEBUG
	stringstream sstr;
#endif

	switch (reason) {
	case CONTEXT_CHANGE_REASON_SIGNAL:
#ifdef SIGNAL_DEBUG
		sstr << "SIGNAL " << info << endl;
		OUTLOG(sstr);
#endif
		sighandler = TRUE;
		tramp.low = tramp.high = 0;
		break;
	case CONTEXT_CHANGE_REASON_SIGRETURN:
#ifdef SIGNAL_DEBUG
		sstr << "SIGRETURN " << endl;
		OUTLOG(sstr);
#endif
		sighandler = FALSE;
		break;
	default:
		break;
	}
}

static VOID Usage(void)
{
	cerr << "This is the ISR PIN tool." << endl;
	cerr << KNOB_BASE::StringKnobSummary() << endl;
}

// This function is called when the application exits
static VOID Fini(INT32 code, VOID *v)
{
	stringstream sstr;

	// Write to a file since cout and cerr maybe closed by the application
	sstr << "Fetch called " << fcallcount << endl;
	sstr << "Last image hits " << image_hits << endl;
	sstr << "My PID was: " << PIN_GetPid() << endl;
	OUTLOG(sstr);
}

static VOID ForceExit(INT32 code)
{
	Fini(code, NULL);
	PIN_ExitApplication(code);
}

BOOL followchild(CHILD_PROCESS childProcess, VOID *val)
{
	int argc;
	CHAR const * const *argv;

	stringstream sstr;
	sstr << "Follow child process: " << CHILD_PROCESS_GetId(childProcess) << endl;
	OUTLOG(sstr);
	return TRUE;
}

void disassemble(INS ins, VOID *v)
{
	stringstream sstr;
	sstr << INS_Disassemble(ins) << endl;
	OUTLOG(sstr);
}

int main(int argc, char **argv)
{
	sqlite3 *db;

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		Usage();
		PIN_ExitApplication(1);
	}

	//OutFile.open(KnobOutputFile.Value().c_str(), ios::app);

#ifdef UNKNOWN_DEBUG
	xed_tables_init();
	xed_decode_init();

	xed_state_zero(&dstate);
	xed_state_init(&dstate, XED_MACHINE_MODE_LEGACY_32,
			XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b);
#endif

#ifdef ISOLATE_MEMORY
	if (!MemoryProtectorInit())
		PIN_ExitApplication(1);
#endif

	keydbfn = KnobKeyDB.Value();
	// Open the key DB to ensure it is at least initially accessible
	if ((db = OpenDB()) == NULL)
		return 1;
	sqlite3_close(db);
	
	// Capture image loading/unloading
	IMG_AddInstrumentFunction(LoadImage, NULL);
	IMG_AddUnloadFunction(UnloadImage, NULL);

#if defined(ISOLATE_MEMORY) || defined(UNKNOWN_DEBUG)
	//TRACE_AddInstrumentFunction(InstrumentTrace, 0);
#endif

	// An empty image to de-randomize unknown code
	// We can also try to read real random data from /dev/random for the
	// seed
	srand((unsigned int)time(NULL));
	random_image = new Image(0, 0);
	uint16_t randkey = (rand() % 65535) + 1;
	random_image->SetKey(&randkey, 2);

	// Handle signals
	PIN_AddContextChangeFunction(ContextSwitch, NULL);

	// Decode instructions when fetching
	PIN_AddFetchFunction(FetchInstruction, NULL);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Add VDSO page to mapped images
	ProcessMMaps();

	// Intercept signals that can received due to an attack 
	PIN_UnblockSignal(SIGSEGV, TRUE);
	PIN_InterceptSignal(SIGSEGV, FaultHandler, 0);
	PIN_UnblockSignal(SIGILL, TRUE);
	PIN_InterceptSignal(SIGILL, FaultHandler, 0);
	PIN_UnblockSignal(SIGABRT, TRUE);
	PIN_InterceptSignal(SIGABRT, FaultHandler, 0);
	PIN_UnblockSignal(SIGFPE, TRUE);
	PIN_InterceptSignal(SIGFPE, FaultHandler, 0);

	// Following the spawned processes
	PIN_AddFollowChildProcessFunction(followchild, 0);

	//INS_AddInstrumentFunction(disassemble, 0);

	// Start the program, never returns
	PIN_StartProgram();

    OutFile.close();
	return 0;
}
