#ifndef _BEACON_H_
#define _BEACON_H_
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif 

typedef struct {
	char * original; 
	char * buffer;   
	int    length;   
	int    size;     
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

typedef struct {
	char * original; 
	char * buffer;   
	int    length;   
	int    size;     
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, const char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, const char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);


#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d
#define CALLBACK_CUSTOM      0x1000
#define CALLBACK_CUSTOM_LAST 0x13ff


DECLSPEC_IMPORT void   BeaconOutput(int type, const char * data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, const char * fmt, ...);


DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();


DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

typedef struct {
	char * ptr;
	size_t size;
} HEAP_RECORD;
#define MASK_SIZE 13

typedef enum {
	PURPOSE_EMPTY,
	PURPOSE_GENERIC_BUFFER,
	PURPOSE_BEACON_MEMORY,
	PURPOSE_SLEEPMASK_MEMORY,
	PURPOSE_BOF_MEMORY,
	PURPOSE_USER_DEFINED_MEMORY = 1000
} ALLOCATED_MEMORY_PURPOSE;

typedef enum {
	LABEL_EMPTY,
	LABEL_BUFFER,
	LABEL_PEHEADER,
	LABEL_TEXT,
	LABEL_RDATA,
	LABEL_DATA,
	LABEL_PDATA,
	LABEL_RELOC,
	LABEL_USER_DEFINED = 1000
} ALLOCATED_MEMORY_LABEL;

typedef enum {
	METHOD_UNKNOWN,
	METHOD_VIRTUALALLOC,
	METHOD_HEAPALLOC,
	METHOD_MODULESTOMP,
	METHOD_NTMAPVIEW,
	METHOD_USER_DEFINED = 1000,
} ALLOCATED_MEMORY_ALLOCATION_METHOD;
typedef struct _HEAPALLOC_INFO {
	PVOID HeapHandle;
	BOOL  DestroyHeap;
} HEAPALLOC_INFO, *PHEAPALLOC_INFO;

typedef struct _MODULESTOMP_INFO {
	HMODULE ModuleHandle;
} MODULESTOMP_INFO, *PMODULESTOMP_INFO;

typedef union _ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION {
	HEAPALLOC_INFO HeapAllocInfo;
	MODULESTOMP_INFO ModuleStompInfo;
	PVOID Custom;
} ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_CLEANUP_INFORMATION {
	BOOL Cleanup;
	ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
	ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
} ALLOCATED_MEMORY_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_SECTION {
	ALLOCATED_MEMORY_LABEL Label; 
	PVOID  BaseAddress;           
	SIZE_T VirtualSize;           
	DWORD  CurrentProtect;        
	DWORD  PreviousProtect;      
	BOOL   MaskSection;           
} ALLOCATED_MEMORY_SECTION, *PALLOCATED_MEMORY_SECTION;

typedef struct _ALLOCATED_MEMORY_REGION {
	ALLOCATED_MEMORY_PURPOSE Purpose;      
	PVOID  AllocationBase;                
	SIZE_T RegionSize;                   
	DWORD Type;                           
	ALLOCATED_MEMORY_SECTION Sections[8];  
	ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation; 
} ALLOCATED_MEMORY_REGION, *PALLOCATED_MEMORY_REGION;

typedef struct {
	ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
} ALLOCATED_MEMORY, *PALLOCATED_MEMORY;

typedef struct {
	unsigned int version;
	char  * sleep_mask_ptr;
	DWORD   sleep_mask_text_size;
	DWORD   sleep_mask_total_size;

	char  * beacon_ptr;
	HEAP_RECORD * heap_records;
	char    mask[MASK_SIZE];

	ALLOCATED_MEMORY allocatedMemory;
} BEACON_INFO, *PBEACON_INFO;

DECLSPEC_IMPORT BOOL   BeaconInformation(PBEACON_INFO info);

DECLSPEC_IMPORT BOOL BeaconAddValue(const char * key, void * ptr);
DECLSPEC_IMPORT void * BeaconGetValue(const char * key);
DECLSPEC_IMPORT BOOL BeaconRemoveValue(const char * key);

#define DATA_STORE_TYPE_EMPTY 0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
	int type;
	DWORD64 hash;
	BOOL masked;
	char* buffer;
	size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

DECLSPEC_IMPORT PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
DECLSPEC_IMPORT void BeaconDataStoreProtectItem(size_t index);
DECLSPEC_IMPORT void BeaconDataStoreUnprotectItem(size_t index);
DECLSPEC_IMPORT size_t BeaconDataStoreMaxEntries();

DECLSPEC_IMPORT char * BeaconGetCustomUserData();

typedef struct
{
	PVOID fnAddr;
	PVOID jmpAddr;
	DWORD sysnum;
} SYSCALL_API_ENTRY, *PSYSCALL_API_ENTRY;

typedef struct
{
	SYSCALL_API_ENTRY ntAllocateVirtualMemory;
	SYSCALL_API_ENTRY ntProtectVirtualMemory;
	SYSCALL_API_ENTRY ntFreeVirtualMemory;
	SYSCALL_API_ENTRY ntGetContextThread;
	SYSCALL_API_ENTRY ntSetContextThread;
	SYSCALL_API_ENTRY ntResumeThread;
	SYSCALL_API_ENTRY ntCreateThreadEx;
	SYSCALL_API_ENTRY ntOpenProcess;
	SYSCALL_API_ENTRY ntOpenThread;
	SYSCALL_API_ENTRY ntClose;
	SYSCALL_API_ENTRY ntCreateSection;
	SYSCALL_API_ENTRY ntMapViewOfSection;
	SYSCALL_API_ENTRY ntUnmapViewOfSection;
	SYSCALL_API_ENTRY ntQueryVirtualMemory;
	SYSCALL_API_ENTRY ntDuplicateObject;
	SYSCALL_API_ENTRY ntReadVirtualMemory;
	SYSCALL_API_ENTRY ntWriteVirtualMemory;
	SYSCALL_API_ENTRY ntReadFile;
	SYSCALL_API_ENTRY ntWriteFile;
	SYSCALL_API_ENTRY ntCreateFile;
} SYSCALL_API, *PSYSCALL_API;

typedef struct
{
	PVOID rtlDosPathNameToNtPathNameUWithStatusAddr;
	PVOID rtlFreeHeapAddr;
	PVOID rtlGetProcessHeapAddr;
} RTL_API, *PRTL_API;

typedef struct
{
	PSYSCALL_API syscalls;
	PRTL_API     rtls;
} BEACON_SYSCALLS, *PBEACON_SYSCALLS;

DECLSPEC_IMPORT BOOL BeaconGetSyscallInformation(PBEACON_SYSCALLS info, BOOL resolveIfNotInitialized);

DECLSPEC_IMPORT LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT LPVOID BeaconVirtualAllocEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualProtectEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT BOOL BeaconGetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
DECLSPEC_IMPORT BOOL BeaconSetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
DECLSPEC_IMPORT DWORD BeaconResumeThread(HANDLE threadHandle);
DECLSPEC_IMPORT HANDLE BeaconOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId);
DECLSPEC_IMPORT HANDLE BeaconOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId);
DECLSPEC_IMPORT BOOL BeaconCloseHandle(HANDLE object);
DECLSPEC_IMPORT BOOL BeaconUnmapViewOfFile(LPCVOID baseAddress);
DECLSPEC_IMPORT SIZE_T BeaconVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
DECLSPEC_IMPORT BOOL BeaconDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
DECLSPEC_IMPORT BOOL BeaconReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL BeaconWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

DECLSPEC_IMPORT VOID BeaconDisableBeaconGate();
DECLSPEC_IMPORT VOID BeaconEnableBeaconGate();

#define DLL_BEACON_USER_DATA 0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32
typedef struct
{
	unsigned int version;
	PSYSCALL_API syscalls;
	char         custom[BEACON_USER_DATA_CUSTOM_SIZE];
	PRTL_API     rtls;
	PALLOCATED_MEMORY allocatedMemory;
} USER_DATA, * PUSER_DATA;

#ifdef __cplusplus
}
#endif 
#endif 