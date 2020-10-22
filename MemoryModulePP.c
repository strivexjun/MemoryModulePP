/*
 * modify by xjun
 */

/*

WIN7 x86 and x64 (Build 7601)

int __stdcall RtlInsertInvertedFunctionTable(PVOID Pointer, PVOID BaseAddress, ULONG uImageSize)
Pointer == LdrpInvertedFunctionTable;

89 48 04 89 01 A3 ?? ?? ?? ?? FF 76 20

.text:7DEBA8E6 89 48 04                                      mov     [eax+4], ecx
.text:7DEBA8E9 89 01                                         mov     [ecx], eax
.text:7DEBA8EB A3 18 02 F7 7D                                mov     dword_7DF70218, eax
.text:7DEBA8F0 FF 76 20                                      push    dword ptr [esi+20h] ; int
.text:7DEBA8F3 FF 76 18                                      push    dword ptr [esi+18h] ; BaseAddress
.text:7DEBA8F6 68 00 22 F7 7D                                push    offset _LdrpInvertedFunctionTable ; Pointer
.text:7DEBA8FB E8 B2 5B FF FF                                call    _RtlInsertInvertedFunctionTable@12 ; RtlInsertInvertedFunctionTable(x,x,x)

/////////////////////////////////////////////////////////////////////////////////////////////////////////

WIN8 x86 and x64 (Build 9600)
int __fastcall RtlInsertInvertedFunctionTable(PVOID BaseAddress, ULONG uImageSize)

33 FF 8B 56 20 8B CB E8

.text:6B2D7980 33 FF                                         xor     edi, edi
.text:6B2D7982
.text:6B2D7982                               loc_6B2D7982:                           ; CODE XREF: LdrpProcessMappedModule(x,x)+160¡üj
.text:6B2D7982                                                                       ; LdrpProcessMappedModule(x,x)+169¡üj ...
.text:6B2D7982 8B 56 20                                      mov     edx, [esi+20h]  ; uImageSize
.text:6B2D7985 8B CB                                         mov     ecx, ebx        ; BaseAddress
.text:6B2D7987 E8 45 0A 00 00                                call    _RtlInsertInvertedFunctionTable@8 ; RtlInsertInvertedFunctionTable(x,x)

/////////////////////////////////////////////////////////////////////////////////////////////////////////

WIN10 x86 and x64 (Build 19041) RleaseId:2004
int __fastcall RtlInsertInvertedFunctionTable(PVOID BaseAddress, ULONG uImageSize)

8B 85 14 FF FF FF 8B 70 50 8B D6 8B 8D F8 FE FF FF E8

.text:4B32A5AB 8B 85 14 FF FF FF                             mov     eax, [ebp+var_EC]
.text:4B32A5B1 8B 70 50                                      mov     esi, [eax+50h]
.text:4B32A5B4 8B D6                                         mov     edx, esi
.text:4B32A5B6 8B 8D F8 FE FF FF                             mov     ecx, [ebp+var_108]
.text:4B32A5BC E8 BE E6 F8 FF                                call    _RtlInsertInvertedFunctionTable@8 ; RtlInsertInvertedFunctionTable(x,x)

WIN10 x86 and x64 (Build 18363) RleaseId:1909
int __fastcall RtlInsertInvertedFunctionTable(PVOID BaseAddress, ULONG uImageSize)

8B 45 FC 8B CF 8B 70 50 8B D6 E8

.text:6A2CF0BE 8B 45 FC                                      mov     eax, [ebp-4]
.text:6A2CF0C1 8B CF                                         mov     ecx, edi
.text:6A2CF0C3 8B 70 50                                      mov     esi, [eax+50h]
.text:6A2CF0C6 8B D6                                         mov     edx, esi
.text:6A2CF0C8 E8 48 C3 F5 FF                                call    _RtlInsertInvertedFunctionTable@8 ; RtlInsertInvertedFunctionTable(x,x)

WIN10 x86 and x64 (Build 18362) RleaseId:1903
int __fastcall RtlInsertInvertedFunctionTable(PVOID BaseAddress, ULONG uImageSize)

8B 45 FC 8B CF 8B 70 50 8B D6 E8

.text:4B32EE53 8B 45 FC                                      mov     eax, [ebp+var_4]
.text:4B32EE56 8B CF                                         mov     ecx, edi
.text:4B32EE58 8B 70 50                                      mov     esi, [eax+50h]
.text:4B32EE5B 8B D6                                         mov     edx, esi
.text:4B32EE5D E8 BB F0 F7 FF                                call    _RtlInsertInvertedFunctionTable@8 ; RtlInsertInvertedFunctionTable(x,x)


WIN10 x86 and x64 (Build 17763) RleaseId:1809
int __fastcall RtlInsertInvertedFunctionTable(PVOID BaseAddress, ULONG uImageSize)

8B 45 FC 8B CF 8B 70 50 8B D6 E8

.text:4B32F593 8B 45 FC                                      mov     eax, [ebp+var_4]
.text:4B32F596 8B CF                                         mov     ecx, edi
.text:4B32F598 8B 70 50                                      mov     esi, [eax+50h]
.text:4B32F59B 8B D6                                         mov     edx, esi
.text:4B32F59D E8 38 8D F8 FF                                call    _RtlInsertInvertedFunctionTable@8 ; RtlInsertInvertedFunctionTable(x,x)


WIN10 x86 and x64 (Build 16299) RleaseId:1709
int __fastcall RtlInsertInvertedFunctionTable(PVOID BaseAddress, ULONG uImageSize)

8B 85 D4 FE FF FF 8B 70 50 8B D6 8B CB E8

.text:4B327344 8B 85 D4 FE FF FF                             mov     eax, [ebp+var_12C]
.text:4B32734A 8B 70 50                                      mov     esi, [eax+50h]
.text:4B32734D 8B D6                                         mov     edx, esi
.text:4B32734F 8B CB                                         mov     ecx, ebx
.text:4B327351 E8 42 7A FB FF                                call    _RtlInsertInvertedFunctionTable@8 ; RtlInsertInvertedFunctionTable(x,x)


WIN10 x86 and x64 (Build 15036) RleaseId:1703
int __fastcall RtlInsertInvertedFunctionTable(PVOID BaseAddress, ULONG uImageSize)

8B 45 F8 8B CE 8B 40 50 8B D0 89 45 F0 E8

.text:4B32DFEC 8B 45 F8                                      mov     eax, [ebp+var_8]
.text:4B32DFEF 8B CE                                         mov     ecx, esi
.text:4B32DFF1 8B 40 50                                      mov     eax, [eax+50h]
.text:4B32DFF4 8B D0                                         mov     edx, eax
.text:4B32DFF6 89 45 F0                                      mov     [ebp+var_10], eax
.text:4B32DFF9 E8 3E 2E FA FF                                call    _RtlInsertInvertedFunctionTable@8 ; RtlInsertInvertedFunctionTable(x,x)


WIN10 x86 and x64 (Build 10240) RleaseId:1507
int __fastcall RtlInsertInvertedFunctionTable(PVOID BaseAddress, ULONG uImageSize)

8B 85 ?? FF FF FF 8B 70 50 8B D6 8B 8D ?? FF FF FF E8

.text:4B31E0CB 8B 85 18 FF FF FF                             mov     eax, [ebp+var_E8]
.text:4B31E0D1 8B 70 50                                      mov     esi, [eax+50h]
.text:4B31E0D4 8B D6                                         mov     edx, esi
.text:4B31E0D6 8B 8D 34 FF FF FF                             mov     ecx, [ebp+BaseAddress]
.text:4B31E0DC E8 E9 50 F9 FF                                call    _RtlInsertInvertedFunctionTable@8 ; RtlInsertInvertedFunctionTable(x,x)

*/


#include <windows.h>
#include <winnt.h>
#include <stddef.h>
#include <tchar.h>
#include <ImageHlp.h>
#ifdef DEBUG_OUTPUT
#include <stdio.h>
#endif

#if _MSC_VER
// Disable warning about data -> function pointer conversion
#pragma warning(disable:4055)
// C4244: conversion from 'uintptr_t' to 'DWORD', possible loss of data.
#pragma warning(error: 4244)
// C4267: conversion from 'size_t' to 'int', possible loss of data.
#pragma warning(error: 4267)

#define inline __inline
#endif

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#include "MemoryModulePP.h"

ULONG	dwMajorVersion = 0;
ULONG	dwMinorVersion = 0;
ULONG	dwBuildNumber = 0;

PVOID	LdrpInvertedFunctionTable = NULL;
typedef int(__stdcall* fnRtlInsertInvertedFunctionTable_Win7)(PVOID Pointer, PVOID BaseAddress, ULONG uImageSize);
fnRtlInsertInvertedFunctionTable_Win7 pfnRtlInsertInvertedFunctionTable_Win7 = NULL;

typedef int(__fastcall* fnRtlInsertInvertedFunctionTable_Win8_Win10)(PVOID BaseAddress, ULONG uImageSize);
fnRtlInsertInvertedFunctionTable_Win8_Win10 pfnRtlInsertInvertedFunctionTable_Win8_Win10 = NULL;

typedef BOOLEAN(__fastcall* fnRtlAddFunctionTable64)(PVOID FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
fnRtlAddFunctionTable64 pfnRtlAddFunctionTable64 = NULL;

static inline LONG
FindPattern(unsigned char* pSrc, unsigned char* pTrait, int nSrcLen, int nTraitLen)
{
	if (IsBadReadPtr(pSrc, sizeof(void*)) == TRUE)
	{
		return -1;
	}
	int i, j, k;
	for (i = 0; i <= (nSrcLen - nTraitLen); i++)
	{
		if (pSrc[i] == pTrait[0])
		{
			k = i;
			j = 0;
			while (j < nTraitLen)
			{
				k++; j++;
				if (pTrait[j] == 0x90)
				{
					continue;
				}
				if (pSrc[k] != pTrait[j])
				{
					break;
				}
			}

			if (j == nTraitLen)
			{
				return i;
			}

		}

	}
	return -1;
}

static inline uintptr_t
AlignValueDown(uintptr_t value, uintptr_t alignment) {
	return value & ~(alignment - 1);
}

static inline LPVOID
AlignAddressDown(LPVOID address, uintptr_t alignment) {
	return (LPVOID)AlignValueDown((uintptr_t)address, alignment);
}

static inline size_t
AlignValueUp(size_t value, size_t alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}

static inline void*
OffsetPointer(void* data, ptrdiff_t offset) {
	return (void*)((uintptr_t)data + offset);
}

static inline void
OutputLastError(const char *msg)
{
#ifndef DEBUG_OUTPUT
	UNREFERENCED_PARAMETER(msg);
#else
	LPVOID tmp;
	char *tmpmsg;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&tmp, 0, NULL);
	tmpmsg = (char *)LocalAlloc(LPTR, strlen(msg) + strlen(tmp) + 3);
	sprintf(tmpmsg, "%s: %s", msg, tmp);
	OutputDebugString(tmpmsg);
	LocalFree(tmpmsg);
	LocalFree(tmp);
#endif
}

static BOOL
CheckSize(size_t size, size_t expected) {
	if (size < expected) {
		SetLastError(ERROR_INVALID_DATA);
		return FALSE;
	}

	return TRUE;
}

static BOOL
CopySections(const unsigned char *data, size_t size, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module)
{
	int i, section_size;
	unsigned char *codeBase = module->codeBase;
	unsigned char *dest;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
	for (i = 0; i < module->headers->FileHeader.NumberOfSections; i++, section++) {
		if (section->SizeOfRawData == 0) {
			// section doesn't contain data in the dll itself, but may define
			// uninitialized data
			section_size = old_headers->OptionalHeader.SectionAlignment;
			if (section_size > 0) {
				dest = (unsigned char *)module->alloc(codeBase + section->VirtualAddress,
					section_size,
					MEM_COMMIT,
					PAGE_READWRITE,
					module->userdata);
				if (dest == NULL) {
					return FALSE;
				}

				// Always use position from file to support alignments smaller
				// than page size (allocation above will align to page size).
				dest = codeBase + section->VirtualAddress;
				// NOTE: On 64bit systems we truncate to 32bit here but expand
				// again later when "PhysicalAddress" is used.
				section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
				memset(dest, 0, section_size);
			}

			// section is empty
			continue;
		}

		if (!CheckSize(size, section->PointerToRawData + section->SizeOfRawData)) {
			return FALSE;
		}

		// commit memory block and copy data from dll
		dest = (unsigned char *)module->alloc(codeBase + section->VirtualAddress,
			section->SizeOfRawData,
			MEM_COMMIT,
			PAGE_READWRITE,
			module->userdata);
		if (dest == NULL) {
			return FALSE;
		}

		// Always use position from file to support alignments smaller
		// than page size (allocation above will align to page size).
		dest = codeBase + section->VirtualAddress;
		memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);
		// NOTE: On 64bit systems we truncate to 32bit here but expand
		// again later when "PhysicalAddress" is used.
		section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
	}

	return TRUE;
}

// Protection flags for memory pages (Executable, Readable, Writeable)
static int ProtectionFlags[2][2][2] = {
	{
		// not executable
		{ PAGE_NOACCESS, PAGE_WRITECOPY },
		{ PAGE_READONLY, PAGE_READWRITE },
	}, {
		// executable
		{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
		{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE },
	},
};

static SIZE_T
GetRealSectionSize(PMEMORYMODULE module, PIMAGE_SECTION_HEADER section) {
	DWORD size = section->SizeOfRawData;
	if (size == 0) {
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size = module->headers->OptionalHeader.SizeOfInitializedData;
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size = module->headers->OptionalHeader.SizeOfUninitializedData;
		}
	}
	return (SIZE_T)size;
}

static BOOL
FinalizeSection(PMEMORYMODULE module, PSECTIONFINALIZEDATA sectionData) {
	DWORD protect, oldProtect;
	BOOL executable;
	BOOL readable;
	BOOL writeable;

	if (sectionData->size == 0) {
		return TRUE;
	}

	if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
		// section is not needed any more and can safely be freed
		if (sectionData->address == sectionData->alignedAddress &&
			(sectionData->last ||
			module->headers->OptionalHeader.SectionAlignment == module->pageSize ||
			(sectionData->size % module->pageSize) == 0)
			) {
			// Only allowed to decommit whole pages
			module->free(sectionData->address, sectionData->size, MEM_DECOMMIT, module->userdata);
		}
		return TRUE;
	}

	// determine protection flags based on characteristics
	executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
	readable = (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
	writeable = (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
	protect = ProtectionFlags[executable][readable][writeable];
	if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
		protect |= PAGE_NOCACHE;
	}

	// change memory access flags
	if (VirtualProtect(sectionData->address, sectionData->size, protect, &oldProtect) == 0) {
		OutputLastError("Error protecting memory page");
		return FALSE;
	}

	return TRUE;
}

static BOOL
FinalizeSections(PMEMORYMODULE module)
{
	int i;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
#ifdef _WIN64
	// "PhysicalAddress" might have been truncated to 32bit above, expand to
	// 64bits again.
	uintptr_t imageOffset = ((uintptr_t)module->headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
	static const uintptr_t imageOffset = 0;
#endif
	SECTIONFINALIZEDATA sectionData;
	sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
	sectionData.alignedAddress = AlignAddressDown(sectionData.address, module->pageSize);
	sectionData.size = GetRealSectionSize(module, section);
	sectionData.characteristics = section->Characteristics;
	sectionData.last = FALSE;
	section++;

	// loop through all sections and change access flags
	for (i = 1; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
		LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
		LPVOID alignedAddress = AlignAddressDown(sectionAddress, module->pageSize);
		SIZE_T sectionSize = GetRealSectionSize(module, section);
		// Combine access flags of all sections that share a page
		// TODO(fancycode): We currently share flags of a trailing large section
		//   with the page of a first small section. This should be optimized.
		if (sectionData.alignedAddress == alignedAddress || (uintptr_t)sectionData.address + sectionData.size >(uintptr_t) alignedAddress) {
			// Section shares page with previous
			if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
			}
			else {
				sectionData.characteristics |= section->Characteristics;
			}
			sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)sectionData.address;
			continue;
		}

		if (!FinalizeSection(module, &sectionData)) {
			return FALSE;
		}
		sectionData.address = sectionAddress;
		sectionData.alignedAddress = alignedAddress;
		sectionData.size = sectionSize;
		sectionData.characteristics = section->Characteristics;
	}
	sectionData.last = TRUE;
	if (!FinalizeSection(module, &sectionData)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL
ExecuteTLS(PMEMORYMODULE module)
{
	unsigned char *codeBase = module->codeBase;
	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK* callback;

	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
	if (directory->VirtualAddress == 0) {
		return TRUE;
	}

	tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
	callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
	if (callback) {
		while (*callback) {
			(*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, NULL);
			callback++;
		}
	}
	return TRUE;
}

static BOOL
PerformBaseRelocation(PMEMORYMODULE module, ptrdiff_t delta)
{
	unsigned char *codeBase = module->codeBase;
	PIMAGE_BASE_RELOCATION relocation;

	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (directory->Size == 0) {
		return (delta == 0);
	}

	relocation = (PIMAGE_BASE_RELOCATION)(codeBase + directory->VirtualAddress);
	for (; relocation->VirtualAddress > 0;) {
		DWORD i;
		unsigned char *dest = codeBase + relocation->VirtualAddress;
		unsigned short *relInfo = (unsigned short*)OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);
		for (i = 0; i < ((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
			// the upper 4 bits define the type of relocation
			int type = *relInfo >> 12;
			// the lower 12 bits define the offset
			int offset = *relInfo & 0xfff;

			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				// skip relocation
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				// change complete 32 bit address
			{
				DWORD *patchAddrHL = (DWORD *)(dest + offset);
				*patchAddrHL += (DWORD)delta;
			}
			break;

#ifdef _WIN64
			case IMAGE_REL_BASED_DIR64:
			{
				ULONGLONG *patchAddr64 = (ULONGLONG *) (dest + offset);
				*patchAddr64 += (ULONGLONG) delta;
			}
			break;
#endif

			default:
				//printf("Unknown relocation: %d\n", type);
				break;
		}
	}

		// advance to next relocation block
		relocation = (PIMAGE_BASE_RELOCATION)OffsetPointer(relocation, relocation->SizeOfBlock);
}
	return TRUE;
}

static BOOL
BuildImportTable(PMEMORYMODULE module)
{
	unsigned char *codeBase = module->codeBase;
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	BOOL result = TRUE;

	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size == 0) {
		return TRUE;
	}

	importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(codeBase + directory->VirtualAddress);
	for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
		uintptr_t *thunkRef;
		FARPROC *funcRef;
		HCUSTOMMODULE *tmp;
		HCUSTOMMODULE handle = module->loadLibrary((LPCSTR)(codeBase + importDesc->Name), module->userdata);
		if (handle == NULL) {
			SetLastError(ERROR_MOD_NOT_FOUND);
			result = FALSE;
			break;
		}

		tmp = (HCUSTOMMODULE *)realloc(module->modules, (module->numModules + 1)*(sizeof(HCUSTOMMODULE)));
		if (tmp == NULL) {
			module->freeLibrary(handle, module->userdata);
			SetLastError(ERROR_OUTOFMEMORY);
			result = FALSE;
			break;
		}
		module->modules = tmp;

		module->modules[module->numModules++] = handle;
		if (importDesc->OriginalFirstThunk) {
			thunkRef = (uintptr_t *)(codeBase + importDesc->OriginalFirstThunk);
			funcRef = (FARPROC *)(codeBase + importDesc->FirstThunk);
		}
		else {
			// no hint table
			thunkRef = (uintptr_t *)(codeBase + importDesc->FirstThunk);
			funcRef = (FARPROC *)(codeBase + importDesc->FirstThunk);
		}
		for (; *thunkRef; thunkRef++, funcRef++) {
			if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
				*funcRef = module->getProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef), module->userdata);
			}
			else {
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
				*funcRef = module->getProcAddress(handle, (LPCSTR)&thunkData->Name, module->userdata);
			}
			if (*funcRef == 0) {
				result = FALSE;
				break;
			}
		}

		if (!result) {
			module->freeLibrary(handle, module->userdata);
			SetLastError(ERROR_PROC_NOT_FOUND);
			break;
		}
	}

	return result;
}

static VOID
InsertExceptionTable(PMEMORYMODULE module)
{
	
#if defined(_WIN64)

	PIMAGE_DATA_DIRECTORY		pDataTable = \
		&module->headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	PIMAGE_RUNTIME_FUNCTION_ENTRY pFuncTable = \
		(PIMAGE_RUNTIME_FUNCTION_ENTRY)((ULONG_PTR)module->codeBase + pDataTable->VirtualAddress);


	if (pfnRtlAddFunctionTable64 != NULL)
	{
		pfnRtlAddFunctionTable64(pFuncTable, pDataTable->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)module->codeBase);
	}

#else
	if (dwMajorVersion == 6 && dwMinorVersion == 1) //WIM7
	{
		if (pfnRtlInsertInvertedFunctionTable_Win7 != NULL)
		{
			pfnRtlInsertInvertedFunctionTable_Win7(LdrpInvertedFunctionTable, module->codeBase, module->headers->OptionalHeader.SizeOfImage);
		}
	}
	else if (dwMajorVersion == 6 && dwMinorVersion == 3) //WIN8
	{
		if (pfnRtlInsertInvertedFunctionTable_Win8_Win10 != NULL)
		{
			pfnRtlInsertInvertedFunctionTable_Win8_Win10(module->codeBase, module->headers->OptionalHeader.SizeOfImage);
		}
	}
	else if (dwMajorVersion == 10 && dwMinorVersion == 0) //WIN10
	{
		if (pfnRtlInsertInvertedFunctionTable_Win8_Win10 != NULL)
		{
			pfnRtlInsertInvertedFunctionTable_Win8_Win10(module->codeBase, module->headers->OptionalHeader.SizeOfImage);
		}
	}
	else
	{
		// not support
	}
#endif
}

static VOID
InitFindExceptPrivateFunc()
{
	PVOID					pNtdllCode;
	ULONG					uNtdllCodeSize;

	PIMAGE_DOS_HEADER		pDosHead;
	PIMAGE_NT_HEADERS		pNtHead;
	PIMAGE_SECTION_HEADER	pSection;

	pDosHead = (PIMAGE_DOS_HEADER)GetModuleHandle(TEXT("ntdll"));
	if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;
	}
	pNtHead = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHead + pDosHead->e_lfanew);
	if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
	{
		return;
	}

	pSection = IMAGE_FIRST_SECTION(pNtHead);

	for (int i = 0; i < pNtHead->FileHeader.NumberOfSections; i++)
	{
		if (stricmp(pSection->Name, ".text") == 0 &&
			(pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE))
		{
			break;
		}
		pSection++;
	}

	pNtdllCode = (PVOID)((ULONG_PTR)pDosHead + pSection->VirtualAddress);
	uNtdllCodeSize = pSection->SizeOfRawData;

	if (dwMajorVersion == 6 && dwMinorVersion == 1) //WIM7
	{
		LONG			lResult;
		LONG			lCallBuf;
		unsigned char	ida_chars[] = {
			0x89, 0x48, 0x04, 0x89, 0x01, 0xA3, 0x90, 0x90, 0x90,
			0x90, 0xFF, 0x76, 0x20
		};

		lResult = FindPattern(pNtdllCode, ida_chars, uNtdllCodeSize, sizeof(ida_chars));
		if (lResult != -1)
		{
			LdrpInvertedFunctionTable = LongToPtr(*(LONG*)((ULONG_PTR)pNtdllCode + lResult + 0x11));
			lCallBuf = *(LONG*)((ULONG_PTR)pNtdllCode + lResult + 0x16);


			pfnRtlInsertInvertedFunctionTable_Win7 = \
				(fnRtlInsertInvertedFunctionTable_Win7)((ULONG_PTR)pNtdllCode + lResult + 0x15 + 0x5 + lCallBuf);

		}

	}
	else if (dwMajorVersion == 6 && dwMinorVersion == 3) //WIN8
	{
		LONG			lResult;
		LONG			lCallBuf;
		unsigned char	ida_chars[] = {
			0x33, 0xFF, 0x8B, 0x56, 0x20, 0x8B, 0xCB, 0xE8
		};
		lResult = FindPattern(pNtdllCode, ida_chars, uNtdllCodeSize, sizeof(ida_chars));
		if (lResult != -1)
		{
			lCallBuf = *(LONG*)((ULONG_PTR)pNtdllCode + lResult + 0x8);

			pfnRtlInsertInvertedFunctionTable_Win8_Win10 = \
				(fnRtlInsertInvertedFunctionTable_Win8_Win10)((ULONG_PTR)pNtdllCode + lResult + 0x7 + 0x5 + lCallBuf);

		}
	}
	else if (dwMajorVersion == 10 && dwMinorVersion == 0) //WIN10
	{
		LONG			lResult;
		LONG			lCallBuf;
		unsigned char	ida_chars1[] = {
			0x8B, 0x85, 0xD4, 0xFE, 0xFF, 0xFF, 0x8B, 0x70, 0x50,
			0x8B, 0xD6, 0x8B, 0xCB, 0xE8
		};
		unsigned char	ida_chars2[] = {
			0x8B, 0x45, 0xF8, 0x8B, 0xCE, 0x8B, 0x40, 0x50, 0x8B,
			0xD0, 0x89, 0x45, 0xF0, 0xE8
		};
		unsigned char	ida_chars3[] = {
			0x8B, 0x85, 0x90, 0xFF, 0xFF, 0xFF, 0x8B, 0x70, 0x50,
			0x8B, 0xD6, 0x8B, 0x8D, 0x90, 0xFF, 0xFF, 0xFF, 0xE8
		};
		unsigned char	ida_chars4[] = {
			0x8B, 0x45, 0xFC, 0x8B, 0xCF, 0x8B, 0x70, 0x50, 0x8B,
			0xD6, 0xE8
		};
		unsigned char	ida_chars5[] = {
			0x8B, 0x85, 0x14, 0xFF, 0xFF, 0xFF, 0x8B, 0x70, 0x50,
			0x8B, 0xD6, 0x8B, 0x8D, 0xF8, 0xFE, 0xFF, 0xFF, 0xE8
		};


		if ((lResult = FindPattern(pNtdllCode, ida_chars1, uNtdllCodeSize, sizeof(ida_chars1))) != -1)
		{
			lCallBuf = *(LONG*)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars1));

			pfnRtlInsertInvertedFunctionTable_Win8_Win10 = \
				(fnRtlInsertInvertedFunctionTable_Win8_Win10)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars1) - 1 + 0x5 + lCallBuf);
		}
		else if ((lResult = FindPattern(pNtdllCode, ida_chars2, uNtdllCodeSize, sizeof(ida_chars2))) != -1)
		{
			lCallBuf = *(LONG*)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars2));

			pfnRtlInsertInvertedFunctionTable_Win8_Win10 = \
				(fnRtlInsertInvertedFunctionTable_Win8_Win10)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars2) - 1 + 0x5 + lCallBuf);
		}
		else if ((lResult = FindPattern(pNtdllCode, ida_chars3, uNtdllCodeSize, sizeof(ida_chars3))) != -1)
		{
			lCallBuf = *(LONG*)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars3));

			pfnRtlInsertInvertedFunctionTable_Win8_Win10 = \
				(fnRtlInsertInvertedFunctionTable_Win8_Win10)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars3) - 1 + 0x5 + lCallBuf);
		}
		else if ((lResult = FindPattern(pNtdllCode, ida_chars4, uNtdllCodeSize, sizeof(ida_chars4))) != -1)
		{
			lCallBuf = *(LONG*)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars4));

			pfnRtlInsertInvertedFunctionTable_Win8_Win10 = \
				(fnRtlInsertInvertedFunctionTable_Win8_Win10)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars4) - 1 + 0x5 + lCallBuf);
		}
		else if ((lResult = FindPattern(pNtdllCode, ida_chars5, uNtdllCodeSize, sizeof(ida_chars5))) != -1)
		{
			lCallBuf = *(LONG*)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars5));

			pfnRtlInsertInvertedFunctionTable_Win8_Win10 = \
				(fnRtlInsertInvertedFunctionTable_Win8_Win10)((ULONG_PTR)pNtdllCode + lResult + sizeof(ida_chars5) - 1 + 0x5 + lCallBuf);
		}
		else
		{
#ifdef _DEBUG
			__debugbreak();
#endif // DEBUG
			// not support;
		}
	}
	else
	{
		// not support
	}

}

LPVOID MemoryDefaultAlloc(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect, void* userdata)
{
	UNREFERENCED_PARAMETER(userdata);
	return VirtualAlloc(address, size, allocationType, protect);
}

BOOL MemoryDefaultFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType, void* userdata)
{
	UNREFERENCED_PARAMETER(userdata);
	return VirtualFree(lpAddress, dwSize, dwFreeType);
}

HCUSTOMMODULE MemoryDefaultLoadLibrary(LPCSTR filename, void *userdata)
{
	HMODULE result;
	UNREFERENCED_PARAMETER(userdata);
	result = LoadLibraryA(filename);
	if (result == NULL) {
		return NULL;
	}

	return (HCUSTOMMODULE)result;
}

FARPROC MemoryDefaultGetProcAddress(HCUSTOMMODULE module, LPCSTR name, void *userdata)
{
	UNREFERENCED_PARAMETER(userdata);
	return (FARPROC)GetProcAddress((HMODULE)module, name);
}

void MemoryDefaultFreeLibrary(HCUSTOMMODULE module, void *userdata)
{
	UNREFERENCED_PARAMETER(userdata);
	FreeLibrary((HMODULE)module);
}

PMEMORYMODULE MemoryLoadLibrary(const void *data, size_t size)
{
	return MemoryLoadLibraryEx(data, size, MemoryDefaultAlloc, MemoryDefaultFree, MemoryDefaultLoadLibrary, MemoryDefaultGetProcAddress, MemoryDefaultFreeLibrary, NULL);
}

PMEMORYMODULE MemoryLoadLibraryEx(const void *data, size_t size,
	CustomAllocFunc allocMemory,
	CustomFreeFunc freeMemory,
	CustomLoadLibraryFunc loadLibrary,
	CustomGetProcAddressFunc getProcAddress,
	CustomFreeLibraryFunc freeLibrary,
	void *userdata)
{
	PMEMORYMODULE result = NULL;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS old_header;
	unsigned char *code, *headers;
	ptrdiff_t locationDelta;
	SYSTEM_INFO sysInfo;
	PIMAGE_SECTION_HEADER section;
	DWORD i;
	size_t optionalSectionSize;
	size_t lastSectionEnd = 0;
	size_t alignedImageSize;

	static BOOL	g_bInit = FALSE;
	if (_InterlockedCompareExchange((LONG*)&g_bInit, TRUE, FALSE) == FALSE)
	{
#if defined(_WIN64)
		pfnRtlAddFunctionTable64 = (fnRtlAddFunctionTable64)GetProcAddress(GetModuleHandle(TEXT("ntdll")), "RtlAddFunctionTable");
#else
		RTL_OSVERSIONINFOW	osinfo = { 0 };
		typedef LONG(__stdcall *fnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
		fnRtlGetVersion pfnRtlGetVersion = (fnRtlGetVersion)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlGetVersion");
		if (pfnRtlGetVersion != NULL && pfnRtlGetVersion(&osinfo) == 0)
		{
			dwMajorVersion = osinfo.dwMajorVersion;
			dwMinorVersion = osinfo.dwMinorVersion;
			dwBuildNumber = osinfo.dwBuildNumber;
			InitFindExceptPrivateFunc();
		}

#endif
	}

	if (!CheckSize(size, sizeof(IMAGE_DOS_HEADER))) {
		return NULL;
	}
	dos_header = (PIMAGE_DOS_HEADER)data;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return NULL;
	}

	if (!CheckSize(size, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS))) {
		return NULL;
	}
	old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(data))[dos_header->e_lfanew];
	if (old_header->Signature != IMAGE_NT_SIGNATURE) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return NULL;
	}

	if (old_header->FileHeader.Machine != HOST_MACHINE) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return NULL;
	}

	if (old_header->OptionalHeader.SectionAlignment & 1) {
		// Only support section alignments that are a multiple of 2
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return NULL;
	}

	section = IMAGE_FIRST_SECTION(old_header);
	optionalSectionSize = old_header->OptionalHeader.SectionAlignment;
	for (i = 0; i < old_header->FileHeader.NumberOfSections; i++, section++) {
		size_t endOfSection;
		if (section->SizeOfRawData == 0) {
			// Section without data in the DLL
			endOfSection = section->VirtualAddress + optionalSectionSize;
		}
		else {
			endOfSection = section->VirtualAddress + section->SizeOfRawData;
		}

		if (endOfSection > lastSectionEnd) {
			lastSectionEnd = endOfSection;
		}
	}

	GetNativeSystemInfo(&sysInfo);
	alignedImageSize = AlignValueUp(old_header->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
	if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return NULL;
	}

	// reserve memory for image of library
	// XXX: is it correct to commit the complete memory region at once?
	//      calling DllEntry raises an exception if we don't...
	code = (unsigned char *)allocMemory((LPVOID)(old_header->OptionalHeader.ImageBase),
		alignedImageSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE,
		userdata);

	if (code == NULL) {
		// try to allocate memory at arbitrary position
		code = (unsigned char *)allocMemory(NULL,
			alignedImageSize,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE,
			userdata);
		if (code == NULL) {
			SetLastError(ERROR_OUTOFMEMORY);
			return NULL;
		}
	}

	result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
	if (result == NULL) {
		freeMemory(code, 0, MEM_RELEASE, userdata);
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}

	result->codeBase = code;
	result->isDLL = (old_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
	result->alloc = allocMemory;
	result->free = freeMemory;
	result->loadLibrary = loadLibrary;
	result->getProcAddress = getProcAddress;
	result->freeLibrary = freeLibrary;
	result->userdata = userdata;
	result->pageSize = sysInfo.dwPageSize;

	if (!CheckSize(size, old_header->OptionalHeader.SizeOfHeaders)) {
		goto error;
	}

	// commit memory for headers
	headers = (unsigned char *)allocMemory(code,
		old_header->OptionalHeader.SizeOfHeaders,
		MEM_COMMIT,
		PAGE_READWRITE,
		userdata);

	// copy PE header to code
	memcpy(headers, dos_header, old_header->OptionalHeader.SizeOfHeaders);
	result->headers = (PIMAGE_NT_HEADERS)&((const unsigned char *)(headers))[dos_header->e_lfanew];

	// update position
	result->headers->OptionalHeader.ImageBase = (uintptr_t)code;

	// copy sections from DLL file block to new memory location
	if (!CopySections((const unsigned char *)data, size, old_header, result)) {
		goto error;
	}

	// adjust base address of imported data
	locationDelta = (ptrdiff_t)(result->headers->OptionalHeader.ImageBase - old_header->OptionalHeader.ImageBase);
	if (locationDelta != 0) {
		//if not exist reloc table?
		if (result->headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0){
			goto error;
		}
		result->isRelocated = PerformBaseRelocation(result, locationDelta);
	}
	else {
		result->isRelocated = TRUE;
	}

	// load required dlls and adjust function table of imports
	if (!BuildImportTable(result)) {
		goto error;
	}

	// mark memory pages depending on section headers and release
	// sections that are marked as "discardable"
	if (!FinalizeSections(result)) {
		goto error;
	}

	// TLS callbacks are executed BEFORE the main loading
	if (!ExecuteTLS(result)) {
		goto error;
	}

	// support exception
	InsertExceptionTable(result);

	// get entry point of loaded library
	if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) {
		if (result->isDLL) {
			DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
			// notify library about attaching to process
			BOOL successfull = (*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);
			if (!successfull) {
				SetLastError(ERROR_DLL_INIT_FAILED);
				goto error;
			}
			result->initialized = TRUE;
		}
		else {
			result->exeEntry = (ExeEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
		}
	}
	else {
		result->exeEntry = NULL;
	}

	return (PMEMORYMODULE)result;

error:
	// cleanup
	MemoryFreeLibrary(result);
	return NULL;
}

static int _compare(const void *a, const void *b)
{
	const struct ExportNameEntry *p1 = (const struct ExportNameEntry*) a;
	const struct ExportNameEntry *p2 = (const struct ExportNameEntry*) b;
	return _stricmp(p1->name, p2->name);
}

static int _find(const void *a, const void *b)
{
	LPCSTR *name = (LPCSTR *)a;
	const struct ExportNameEntry *p = (const struct ExportNameEntry*) b;
	return _stricmp(*name, p->name);
}

FARPROC MemoryGetProcAddress(PMEMORYMODULE mod, LPCSTR name)
{
	PMEMORYMODULE module = (PMEMORYMODULE)mod;
	unsigned char *codeBase = module->codeBase;
	DWORD idx = 0;
	PIMAGE_EXPORT_DIRECTORY exports;
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (directory->Size == 0) {
		// no export table found
		SetLastError(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	exports = (PIMAGE_EXPORT_DIRECTORY)(codeBase + directory->VirtualAddress);
	if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0) {
		// DLL doesn't export anything
		SetLastError(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	if (HIWORD(name) == 0) {
		// load function by ordinal value
		if (LOWORD(name) < exports->Base) {
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}

		idx = LOWORD(name) - exports->Base;
	}
	else if (!exports->NumberOfNames) {
		SetLastError(ERROR_PROC_NOT_FOUND);
		return NULL;
	}
	else {
		const struct ExportNameEntry *found;

		// Lazily build name table and sort it by names
		if (!module->nameExportsTable) {
			DWORD i;
			DWORD *nameRef = (DWORD *)(codeBase + exports->AddressOfNames);
			WORD *ordinal = (WORD *)(codeBase + exports->AddressOfNameOrdinals);
			struct ExportNameEntry *entry = (struct ExportNameEntry*) malloc(exports->NumberOfNames * sizeof(struct ExportNameEntry));
			module->nameExportsTable = entry;
			if (!entry) {
				SetLastError(ERROR_OUTOFMEMORY);
				return NULL;
			}
			for (i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++, entry++) {
				entry->name = (const char *)(codeBase + (*nameRef));
				entry->idx = *ordinal;
			}
			qsort(module->nameExportsTable,
				exports->NumberOfNames,
				sizeof(struct ExportNameEntry), _compare);
		}

		// search function name in list of exported names with binary search
		found = (const struct ExportNameEntry*) bsearch(&name,
			module->nameExportsTable,
			exports->NumberOfNames,
			sizeof(struct ExportNameEntry), _find);
		if (!found) {
			// exported symbol not found
			SetLastError(ERROR_PROC_NOT_FOUND);
			return NULL;
		}

		idx = found->idx;
	}

	if (idx > exports->NumberOfFunctions) {
		// name <-> ordinal number don't match
		SetLastError(ERROR_PROC_NOT_FOUND);
		return NULL;
	}

	// AddressOfFunctions contains the RVAs to the "real" functions
	return (FARPROC)(LPVOID)(codeBase + (*(DWORD *)(codeBase + exports->AddressOfFunctions + (idx * 4))));
}

void MemoryFreeLibrary(PMEMORYMODULE mod)
{
	PMEMORYMODULE module = (PMEMORYMODULE)mod;

	if (module == NULL) {
		return;
	}
	if (module->initialized) {
		// notify library about detaching from process
		DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(module->codeBase + module->headers->OptionalHeader.AddressOfEntryPoint);
		(*DllEntry)((HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, 0);
	}

	free(module->nameExportsTable);
	if (module->modules != NULL) {
		// free previously opened libraries
		int i;
		for (i = 0; i < module->numModules; i++) {
			if (module->modules[i] != NULL) {
				module->freeLibrary(module->modules[i], module->userdata);
			}
		}

		free(module->modules);
	}

	if (module->codeBase != NULL) {
		// release memory of library
		module->free(module->codeBase, 0, MEM_RELEASE, module->userdata);
	}

	HeapFree(GetProcessHeap(), 0, module);
}

int MemoryCallEntryPoint(PMEMORYMODULE mod)
{
	PMEMORYMODULE module = (PMEMORYMODULE)mod;

	if (module == NULL || module->isDLL || module->exeEntry == NULL || !module->isRelocated) {
		return -1;
	}

	return module->exeEntry();
}

#define DEFAULT_LANGUAGE        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)

HMEMORYRSRC MemoryFindResource(PMEMORYMODULE module, LPCTSTR name, LPCTSTR type)
{
	return MemoryFindResourceEx(module, name, type, DEFAULT_LANGUAGE);
}

static PIMAGE_RESOURCE_DIRECTORY_ENTRY _MemorySearchResourceEntry(
	void *root,
	PIMAGE_RESOURCE_DIRECTORY resources,
	LPCTSTR key)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resources + 1);
	PIMAGE_RESOURCE_DIRECTORY_ENTRY result = NULL;
	DWORD start;
	DWORD end;
	DWORD middle;

	if (!IS_INTRESOURCE(key) && key[0] == TEXT('#')) {
		// special case: resource id given as string
		TCHAR *endpos = NULL;
		long int tmpkey = (WORD)_tcstol((TCHAR *)&key[1], &endpos, 10);
		if (tmpkey <= 0xffff && lstrlen(endpos) == 0) {
			key = MAKEINTRESOURCE(tmpkey);
		}
	}

	// entries are stored as ordered list of named entries,
	// followed by an ordered list of id entries - we can do
	// a binary search to find faster...
	if (IS_INTRESOURCE(key)) {
		WORD check = (WORD)(uintptr_t)key;
		start = resources->NumberOfNamedEntries;
		end = start + resources->NumberOfIdEntries;

		while (end > start) {
			WORD entryName;
			middle = (start + end) >> 1;
			entryName = (WORD)entries[middle].Name;
			if (check < entryName) {
				end = (end != middle ? middle : middle - 1);
			}
			else if (check > entryName) {
				start = (start != middle ? middle : middle + 1);
			} else {
				result = &entries[middle];
				break;
			}
		}
	} else {
		LPCWSTR searchKey;
		size_t searchKeyLen = _tcslen(key);
#if defined(UNICODE)
		searchKey = key;
#else
		// Resource names are always stored using 16bit characters, need to
		// convert string we search for.
#define MAX_LOCAL_KEY_LENGTH 2048
		// In most cases resource names are short, so optimize for that by
		// using a pre-allocated array.
		wchar_t _searchKeySpace[MAX_LOCAL_KEY_LENGTH + 1];
		LPWSTR _searchKey;
		if (searchKeyLen > MAX_LOCAL_KEY_LENGTH) {
			size_t _searchKeySize = (searchKeyLen + 1) * sizeof(wchar_t);
			_searchKey = (LPWSTR)malloc(_searchKeySize);
			if (_searchKey == NULL) {
				SetLastError(ERROR_OUTOFMEMORY);
				return NULL;
			}
		}
		else {
			_searchKey = &_searchKeySpace[0];
		}

		mbstowcs(_searchKey, key, searchKeyLen);
		_searchKey[searchKeyLen] = 0;
		searchKey = _searchKey;
#endif
		start = 0;
		end = resources->NumberOfNamedEntries;
		while (end > start) {
			int cmp;
			PIMAGE_RESOURCE_DIR_STRING_U resourceString;
			middle = (start + end) >> 1;
			resourceString = (PIMAGE_RESOURCE_DIR_STRING_U)OffsetPointer(root, entries[middle].Name & 0x7FFFFFFF);
			cmp = _wcsnicmp(searchKey, resourceString->NameString, resourceString->Length);
			if (cmp == 0) {
				// Handle partial match
				if (searchKeyLen > resourceString->Length) {
					cmp = 1;
				}
				else if (searchKeyLen < resourceString->Length) {
					cmp = -1;
				}
			}
			if (cmp < 0) {
				end = (middle != end ? middle : middle - 1);
			}
			else if (cmp > 0) {
				start = (middle != start ? middle : middle + 1);
			}
			else {
				result = &entries[middle];
				break;
			}
		}
#if !defined(UNICODE)
		if (searchKeyLen > MAX_LOCAL_KEY_LENGTH) {
			free(_searchKey);
		}
#undef MAX_LOCAL_KEY_LENGTH
#endif
	}

	return result;
}

HMEMORYRSRC MemoryFindResourceEx(PMEMORYMODULE module, LPCTSTR name, LPCTSTR type, WORD language)
{
	unsigned char *codeBase = ((PMEMORYMODULE)module)->codeBase;
	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY((PMEMORYMODULE)module, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	PIMAGE_RESOURCE_DIRECTORY rootResources;
	PIMAGE_RESOURCE_DIRECTORY nameResources;
	PIMAGE_RESOURCE_DIRECTORY typeResources;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundType;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundName;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY foundLanguage;
	if (directory->Size == 0) {
		// no resource table found
		SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return NULL;
	}

	if (language == DEFAULT_LANGUAGE) {
		// use language from current thread
		language = LANGIDFROMLCID(GetThreadLocale());
	}

	// resources are stored as three-level tree
	// - first node is the type
	// - second node is the name
	// - third node is the language
	rootResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress);
	foundType = _MemorySearchResourceEntry(rootResources, rootResources, type);
	if (foundType == NULL) {
		SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
		return NULL;
	}

	typeResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress + (foundType->OffsetToData & 0x7fffffff));
	foundName = _MemorySearchResourceEntry(rootResources, typeResources, name);
	if (foundName == NULL) {
		SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
		return NULL;
	}

	nameResources = (PIMAGE_RESOURCE_DIRECTORY)(codeBase + directory->VirtualAddress + (foundName->OffsetToData & 0x7fffffff));
	foundLanguage = _MemorySearchResourceEntry(rootResources, nameResources, (LPCTSTR)(uintptr_t)language);
	if (foundLanguage == NULL) {
		// requested language not found, use first available
		if (nameResources->NumberOfIdEntries == 0) {
			SetLastError(ERROR_RESOURCE_LANG_NOT_FOUND);
			return NULL;
		}

		foundLanguage = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(nameResources + 1);
	}

	return (codeBase + directory->VirtualAddress + (foundLanguage->OffsetToData & 0x7fffffff));
}

DWORD MemorySizeofResource(PMEMORYMODULE module, HMEMORYRSRC resource)
{
	PIMAGE_RESOURCE_DATA_ENTRY entry;
	UNREFERENCED_PARAMETER(module);
	entry = (PIMAGE_RESOURCE_DATA_ENTRY)resource;
	if (entry == NULL) {
		return 0;
	}

	return entry->Size;
}

LPVOID MemoryLoadResource(PMEMORYMODULE module, HMEMORYRSRC resource)
{
	unsigned char *codeBase = ((PMEMORYMODULE)module)->codeBase;
	PIMAGE_RESOURCE_DATA_ENTRY entry = (PIMAGE_RESOURCE_DATA_ENTRY)resource;
	if (entry == NULL) {
		return NULL;
	}

	return codeBase + entry->OffsetToData;
}

int
MemoryLoadString(PMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize)
{
	return MemoryLoadStringEx(module, id, buffer, maxsize, DEFAULT_LANGUAGE);
}

int
MemoryLoadStringEx(PMEMORYMODULE module, UINT id, LPTSTR buffer, int maxsize, WORD language)
{
	HMEMORYRSRC resource;
	PIMAGE_RESOURCE_DIR_STRING_U data;
	DWORD size;
	if (maxsize == 0) {
		return 0;
	}

	resource = MemoryFindResourceEx(module, MAKEINTRESOURCE((id >> 4) + 1), RT_STRING, language);
	if (resource == NULL) {
		buffer[0] = 0;
		return 0;
}

	data = (PIMAGE_RESOURCE_DIR_STRING_U)MemoryLoadResource(module, resource);
	id = id & 0x0f;
	while (id--) {
		data = (PIMAGE_RESOURCE_DIR_STRING_U)OffsetPointer(data, (data->Length + 1) * sizeof(WCHAR));
	}
	if (data->Length == 0) {
		SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
		buffer[0] = 0;
		return 0;
	}

	size = data->Length;
	if (size >= (DWORD)maxsize) {
		size = maxsize;
	}
	else {
		buffer[size] = 0;
	}
#if defined(UNICODE)
	wcsncpy(buffer, data->NameString, size);
#else
	wcstombs(buffer, data->NameString, size);
#endif
	return size;
}

#ifdef TESTSUITE
#include <stdio.h>

#ifndef PRIxPTR
#ifdef _WIN64
#define PRIxPTR "I64x"
#else
#define PRIxPTR "x"
#endif
#endif

static const uintptr_t AlignValueDownTests[][3] = {
	{16, 16, 16},
	{17, 16, 16},
	{32, 16, 32},
	{33, 16, 32},
#ifdef _WIN64
	{0x12345678abcd1000, 0x1000, 0x12345678abcd1000},
	{0x12345678abcd101f, 0x1000, 0x12345678abcd1000},
#endif
	{0, 0, 0},
};

static const uintptr_t AlignValueUpTests[][3] = {
	{16, 16, 16},
	{17, 16, 32},
	{32, 16, 32},
	{33, 16, 48},
#ifdef _WIN64
	{0x12345678abcd1000, 0x1000, 0x12345678abcd1000},
	{0x12345678abcd101f, 0x1000, 0x12345678abcd2000},
#endif
	{0, 0, 0},
};

BOOL MemoryModuleTestsuite() {
	BOOL success = TRUE;
	size_t idx;
	for (idx = 0; AlignValueDownTests[idx][0]; ++idx) {
		const uintptr_t* tests = AlignValueDownTests[idx];
		uintptr_t value = AlignValueDown(tests[0], tests[1]);
		if (value != tests[2]) {
			printf("AlignValueDown failed for 0x%" PRIxPTR "/0x%" PRIxPTR ": expected 0x%" PRIxPTR ", got 0x%" PRIxPTR "\n",
				tests[0], tests[1], tests[2], value);
			success = FALSE;
		}
	}
	for (idx = 0; AlignValueDownTests[idx][0]; ++idx) {
		const uintptr_t* tests = AlignValueUpTests[idx];
		uintptr_t value = AlignValueUp(tests[0], tests[1]);
		if (value != tests[2]) {
			printf("AlignValueUp failed for 0x%" PRIxPTR "/0x%" PRIxPTR ": expected 0x%" PRIxPTR ", got 0x%" PRIxPTR "\n",
				tests[0], tests[1], tests[2], value);
			success = FALSE;
		}
	}
	if (success) {
		printf("OK\n");
	}
	return success;
}
#endif
