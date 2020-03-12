#ifndef WIN_UNIXLIBFUNCS_H
#define WIN_UNIXLIBFUNCS_H

#ifdef __cplusplus
extern "C" {
#endif

#define PROT_NONE       0
#define PROT_READ       1
#define PROT_WRITE      2
#define PROT_EXEC       4

#define MAP_FILE        0
#define MAP_SHARED      1
#define MAP_PRIVATE     2
#define MAP_TYPE        0xf
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS

#define MAP_FAILED      ((void *)-1)
#define UNMAP_FAILED -1

/* mmap for windows */
void *mmap (void *ptr, long size, long prot, long type, long handle, long arg);
/* munmap for windows */
long munmap (void *ptr, long size);

#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif

#endif //WIN_UNIXLIBFUNCS_H
