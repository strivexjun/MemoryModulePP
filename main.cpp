#include <stdio.h>
#include <windows.h>

#include "resource.h"
#include "MemoryModulePP.h"

BOOL LoadDllFromRes(PVOID *pDllData, DWORD *dwDllSize)
{
	HMODULE		hInstance = GetModuleHandle(NULL);
	HRSRC		hRes;

#if defined(_WIN64)
	hRes = FindResource(hInstance, MAKEINTRESOURCE(IDR_DLL_X641),TEXT("DLL_X64"));
#else
	hRes = FindResource(hInstance, MAKEINTRESOURCE(IDR_DLL_X861), TEXT("DLL_X86"));
#endif
	if (hRes == NULL)
	{
		return FALSE;
	}

	*pDllData = (PVOID)LoadResource(hInstance, hRes);
	*dwDllSize = SizeofResource(hInstance, hRes);

	return TRUE;
}

int main()
{
	PVOID			pDllData = NULL;
	DWORD			dwDllSize = 0;

	PMEMORYMODULE	pMemdll = NULL;

	if (LoadDllFromRes(&pDllData,&dwDllSize))
	{
		pMemdll = MemoryLoadLibrary(pDllData, dwDllSize);
		if (pMemdll != NULL)
		{
			MemoryFreeLibrary(pMemdll);
		}
	}

	getchar();
}