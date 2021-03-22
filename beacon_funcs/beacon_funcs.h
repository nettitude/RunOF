#include <stdio.h>
#include <stdint.h>

WINBASEAPI int __cdecl MSVCRT$puts(const char * str);
WINBASEAPI int __cdecl MSVCRT$vprintf(const char * __restrict__ format,va_list arg);
WINBASEAPI int __cdecl MSVCRT$printf(const char * __restrict__ format, ...);
WINBASEAPI int __cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * __restrict__ d,size_t n,const char * __restrict__ format,va_list arg);
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source);

char *global_buffer;
uint32_t global_buffer_maxlen;

char *argument_buffer;
uint32_t argument_buffer_length;

enum arg_types {
	BINARY,
	INT_32,
	INT_16,
	STR,
	WCHR_STR
};

char empty_string[1] = "\x00";

// declare this as an import, so that our loader can fill in its address
DECLSPEC_IMPORT void go(IN PCHAR Buffer, IN ULONG Length);


/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Cobalt Strike 4.1.
 */

/* data API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

extern void    BeaconDataParse(datap * parser, char * buffer, int size);
extern int     BeaconDataInt(datap * parser);
extern short   BeaconDataShort(datap * parser);
extern int     BeaconDataLength(datap * parser);
extern char *  BeaconDataExtract(datap * parser, int * size);

/* format API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

extern void   BeaconPrintf(int type, char * fmt, ...);
extern void   BeaconOutput(int type, char * data, int len);

/* Token Functions */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

