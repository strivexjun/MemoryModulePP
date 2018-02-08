
#include <windows.h>


void Test()
{
	MessageBox(NULL, TEXT("memory module load successfuly."), TEXT("info"), MB_ICONINFORMATION);

	PCHAR	p = NULL;
	__try{
		*p = '0';
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		MessageBox(NULL, TEXT("exception 1"), TEXT("info"), MB_ICONINFORMATION);
	}

}


BOOL APIENTRY DllMain(HMODULE hDllHandle, DWORD dwReason, LPVOID lpreserved)
{
	switch (dwReason){
	case DLL_PROCESS_ATTACH:// process attach
	{
		DisableThreadLibraryCalls(hDllHandle);
		Test();
		break;
	}
	case DLL_PROCESS_DETACH:{// process detach
		break;
	}
	default:
		break;
	}

	return TRUE;
}