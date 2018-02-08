/*
* modify by xjun
*/

#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <windows.h>

typedef void *HMEMORYRSRC;

typedef void *HCUSTOMMODULE;

#ifdef __cplusplus
extern "C" {
#endif

typedef LPVOID (*CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
typedef BOOL (*CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
typedef HCUSTOMMODULE (*CustomLoadLibraryFunc)(LPCSTR, void *);
typedef FARPROC (*CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void *);
typedef void (*CustomFreeLibraryFunc)(HCUSTOMMODULE, void *);

struct ExportNameEntry {
	LPCSTR name;
	WORD idx;
};

typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI *ExeEntryProc)(void);

typedef struct {
	PIMAGE_NT_HEADERS headers;
	unsigned char *codeBase;
	HCUSTOMMODULE *modules;
	int numModules;
	BOOL initialized;
	BOOL isDLL;
	BOOL isRelocated;
	CustomAllocFunc alloc;
	CustomFreeFunc free;
	CustomLoadLibraryFunc loadLibrary;
	CustomGetProcAddressFunc getProcAddress;
	CustomFreeLibraryFunc freeLibrary;
	struct ExportNameEntry *nameExportsTable;
	void *userdata;
	ExeEntryProc exeEntry;
	DWORD pageSize;
} MEMORYMODULE, *PMEMORYMODULE;

typedef struct {
	LPVOID address;
	LPVOID alignedAddress;
	SIZE_T size;
	DWORD characteristics;
	BOOL last;
} SECTIONFINALIZEDATA, *PSECTIONFINALIZEDATA;

#define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]

/**
 * Load EXE/DLL from memory location with the given size.
 *
 * All dependencies are resolved using default LoadLibrary/GetProcAddress
 * calls through the Windows API.
 */
PMEMORYMODULE MemoryLoadLibrary(const void *, size_t);

/**
 * Load EXE/DLL from memory location with the given size using custom dependency
 * resolvers.
 *
 * Dependencies will be resolved using passed callback methods.
 */
PMEMORYMODULE MemoryLoadLibraryEx(const void *, size_t,
    CustomAllocFunc,
    CustomFreeFunc,
    CustomLoadLibraryFunc,
    CustomGetProcAddressFunc,
    CustomFreeLibraryFunc,
    void *);

/**
 * Get address of exported method. Supports loading both by name and by
 * ordinal value.
 */
FARPROC MemoryGetProcAddress(PMEMORYMODULE, LPCSTR);

/**
 * Free previously loaded EXE/DLL.
 */
void MemoryFreeLibrary(PMEMORYMODULE);

/**
 * Execute entry point (EXE only). The entry point can only be executed
 * if the EXE has been loaded to the correct base address or it could
 * be relocated (i.e. relocation information have not been stripped by
 * the linker).
 *
 * Important: calling this function will not return, i.e. once the loaded
 * EXE finished running, the process will terminate.
 *
 * Returns a negative value if the entry point could not be executed.
 */
int MemoryCallEntryPoint(PMEMORYMODULE);

/**
 * Find the location of a resource with the specified type and name.
 */
HMEMORYRSRC MemoryFindResource(PMEMORYMODULE, LPCTSTR, LPCTSTR);

/**
 * Find the location of a resource with the specified type, name and language.
 */
HMEMORYRSRC MemoryFindResourceEx(PMEMORYMODULE, LPCTSTR, LPCTSTR, WORD);

/**
 * Get the size of the resource in bytes.
 */
DWORD MemorySizeofResource(PMEMORYMODULE, HMEMORYRSRC);

/**
 * Get a pointer to the contents of the resource.
 */
LPVOID MemoryLoadResource(PMEMORYMODULE, HMEMORYRSRC);

/**
 * Load a string resource.
 */
int MemoryLoadString(PMEMORYMODULE, UINT, LPTSTR, int);

/**
 * Load a string resource with a given language.
 */
int MemoryLoadStringEx(PMEMORYMODULE, UINT, LPTSTR, int, WORD);

/**
* Default implementation of CustomAllocFunc that calls VirtualAlloc
* internally to allocate memory for a library
*
* This is the default as used by MemoryLoadLibrary.
*/
LPVOID MemoryDefaultAlloc(LPVOID, SIZE_T, DWORD, DWORD, void *);

/**
* Default implementation of CustomFreeFunc that calls VirtualFree
* internally to free the memory used by a library
*
* This is the default as used by MemoryLoadLibrary.
*/
BOOL MemoryDefaultFree(LPVOID, SIZE_T, DWORD, void *);

/**
 * Default implementation of CustomLoadLibraryFunc that calls LoadLibraryA
 * internally to load an additional libary.
 *
 * This is the default as used by MemoryLoadLibrary.
 */
HCUSTOMMODULE MemoryDefaultLoadLibrary(LPCSTR, void *);

/**
 * Default implementation of CustomGetProcAddressFunc that calls GetProcAddress
 * internally to get the address of an exported function.
 *
 * This is the default as used by MemoryLoadLibrary.
 */
FARPROC MemoryDefaultGetProcAddress(HCUSTOMMODULE, LPCSTR, void *);

/**
 * Default implementation of CustomFreeLibraryFunc that calls FreeLibrary
 * internally to release an additional libary.
 *
 * This is the default as used by MemoryLoadLibrary.
 */
void MemoryDefaultFreeLibrary(HCUSTOMMODULE, void *);

#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER
