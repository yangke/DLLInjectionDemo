#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <tchar.h>
#include "DoInjectionMain.h"

#pragma comment(lib,"th32.lib")
#pragma comment(lib,"Advapi32.lib")

//这个路径很有意思，这个路径是相对于目标进程的，而不是自身进程。
//所以要么写成绝对路径，要么写成相对于目标进程的相对路径。
//如果写成相对于自身的路径就要麻烦了，本程序就找不到DLL文件了。
const char *pcDllName = "MfcHookApi.dll";        //DLL文件的路径
HANDLE hSnap = 0, hThreadHandle = 0, hRemoteProcess32 = 0, hTokenHandle = 0;
PROCESSENTRY32 procEntry32;
BOOL bNext = FALSE, bWrittenResult = FALSE;
TOKEN_PRIVILEGES tokenPower;
LUID luidPower;
LPVOID pRemoteBuf = NULL;
FARPROC fnDllKernel32;
size_t sizeWritten = 0;
DWORD dwThreadId = 0;

//LPWSTR pcProsessName = (LPWSTR)(_T("DoWin32Test.exe"));   //要注入的进程名(目标进程名)
//char pcProsessName[] ="DoWin32Test.exe";   //要注入的进程名(目标进程名)
char pcProsessName[] = "explorer.exe";   //要注入的进程名(目标进程名)

int main()
{
	IsVistaOrLater();
	SetPrivilege(SE_DEBUG_NAME, TRUE);
	//InjectProcess();
	
	InjectCreateProcess();
	getchar();
	return 0;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		_tprintf(_T("OpenProcessToken error: %u\r\n"), GetLastError());
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL,
		lpszPrivilege,
		&luid))
	{
		_tprintf(_T("LookupPrivilegeValue error: %u\r\n"), GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		_tprintf(_T("AdjustTokenPrivileges error: %u\r\n"), GetLastError());
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		_tprintf(_T("The token does not have the specified privilege. \r\n"));
		return FALSE;
	}
	return TRUE;
}

BOOL IsVistaOrLater()
{

	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	//OSVERSIONINFOEX osvix;
	//ZeroMemory(&osvix,sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);
	printf("network terminal v%ld.%ld,%s,platform:%ld,build number:%ld\r\n", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.szCSDVersion, osvi.dwPlatformId, osvi.dwBuildNumber);
	if (osvi.dwMajorVersion >= 6)
		return TRUE;
	return FALSE;
}

BOOL InjectProcess()
{
	procEntry32.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bNext = Process32First(hSnap, &procEntry32);
	while (bNext)
	{
		if (!strcmp(procEntry32.szExeFile, pcProsessName))        //--->>
		{
			hRemoteProcess32 = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 1, procEntry32.th32ProcessID);
			break;
		}
		bNext = Process32Next(hSnap, &procEntry32);
	}
	CloseHandle(hSnap);
	pRemoteBuf = VirtualAllocEx(hRemoteProcess32, NULL, strlen(pcDllName), MEM_COMMIT, PAGE_READWRITE);
	bWrittenResult = WriteProcessMemory(hRemoteProcess32, pRemoteBuf, pcDllName, strlen(pcDllName), (ULONG*)&sizeWritten);
	if (bWrittenResult)
	{
		printf("InjectCreate()-->WriteProcessMemory() Success,written size:%ld,buffer address:%16X\r\n", sizeWritten, pRemoteBuf);
	}
	else
	{
		printf("InjectCreate()-->WriteProcessMemory() Error:%ld\r\n", GetLastError());
	}
	fnDllKernel32 = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryA");

	//hThreadHandle=CreateRemoteThread(hRemoteProcess32,NULL,0,(LPTHREAD_START_ROUTINE)fnDllKernel32,pAllocMemory,0,&dwThreadId);
	//if (hThreadHandle&&dwThreadId)
	//{
	//  printf("CreateRemoteThread Success,Handle:%ld,Thread Id:%ld\r\n",hThreadHandle,dwThreadId);
	//} 
	//else
	//{
	//  printf("CreateRemoteThread Error:%ld\r\n",GetLastError());
	//}
	InjectCreateThread(hRemoteProcess32, (LPTHREAD_START_ROUTINE)fnDllKernel32, pRemoteBuf);
	//MsicCreateRemoteThread(hRemoteProcess32,(LPTHREAD_START_ROUTINE)fnDllKernel32,pRemoteBuf);
	VirtualFreeEx(hRemoteProcess32, pRemoteBuf, 0, MEM_RELEASE);
	CloseHandle(hRemoteProcess32);
	return TRUE;
}
/*
void create()
{
	LPWSTR szCommandLine = LPWSTR(_T("C:\\Windows\\System32\\notepad.exe"));
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	si.dwFlags = STARTF_USESHOWWINDOW;//指定wShowWindow成员有效
	si.wShowWindow = TRUE;//此成员设为TRUE的话则显示新建进程的主窗口
	BOOL bRet = CreateProcess(
		NULL,//不在此指定可执行文件的文件名
		szCommandLine,//命令行参数
		NULL,//默认进程安全性
		NULL,//默认进程安全性
		FALSE,//指定当前进程内句柄不可以被子进程继承
		CREATE_NEW_CONSOLE,//为新进程创建一个新的控制台窗口
		NULL,//使用本进程的环境变量
		NULL,//使用本进程的驱动器和目录
		&si,
		&pi);
	if (bRet)
	{
		//不使用的句柄最好关掉
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		printf("新进程的ID号：%d\n", pi.dwProcessId);
		printf("新进程的主线程ID号：%d\n", pi.dwThreadId);
	}
	else {
		printf("WWWWXXXXFFFFFF Error:%ld\r\n", GetLastError());
	}
}*/

BOOL InjectCreateProcess()
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	procEntry32.dwSize = sizeof(PROCESSENTRY32);
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	//create();


	//wprintf(_T("%s\n"),pcProsessName);
	printf("%s\n", pcProsessName);
	//CreateProcess(NULL, LPWSTR(_T("DoWin32Test.exe")), NULL, NULL, false, 0, NULL, NULL, &si, &pi);
	CreateProcess(NULL, pcProsessName, NULL, NULL, false, 0, NULL, NULL, &si, &pi);
	hRemoteProcess32 = pi.hProcess;
	printf("waiting for 1 seconds please.\r\n");
	for (int i = 0; i<1; i++)
	{
		Sleep(1000);
		printf(".");
	}
	printf("\r\n");
	pRemoteBuf = VirtualAllocEx(hRemoteProcess32, NULL, strlen(pcDllName), MEM_COMMIT, PAGE_READWRITE);
	bWrittenResult = WriteProcessMemory(hRemoteProcess32, pRemoteBuf, pcDllName, strlen(pcDllName), (ULONG*)&sizeWritten);
	if (bWrittenResult)
	{
		printf("InjectCreate()-->WriteProcessMemory() Success,written size:%ld,buffer address:%16X\r\n", sizeWritten, pRemoteBuf);
	}
	else
	{
		printf("InjectCreate()-->WriteProcessMemory() Error:%ld\r\n", GetLastError());
	}
	fnDllKernel32 = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryA");

	//hThreadHandle=CreateRemoteThread(hRemoteProcess32,NULL,0,(LPTHREAD_START_ROUTINE)fnDllKernel32,pAllocMemory,0,&dwThreadId);
	//if (hThreadHandle&&dwThreadId)
	//{
	//  printf("CreateRemoteThread Success,Handle:%ld,Thread Id:%ld\r\n",hThreadHandle,dwThreadId);
	//} 
	//else
	//{
	//  printf("CreateRemoteThread Error:%ld\r\n",GetLastError());
	//}
	//InjectCreateThread(hRemoteProcess32, (LPTHREAD_START_ROUTINE)fnDllKernel32, pRemoteBuf);
	MsicCreateRemoteThread(hRemoteProcess32, (LPTHREAD_START_ROUTINE)fnDllKernel32, pRemoteBuf);
	//VirtualFreeEx(hRemoteProcess32, pRemoteBuf, 0, MEM_RELEASE);;
	//CloseHandle(hRemoteProcess32);
	return TRUE;
}

BOOL InjectCreateThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	HANDLE      hThread = NULL;
	FARPROC     pFunc = NULL;
	if (IsVistaOrLater())    // Vista, 7, Server2008
	{
		printf("Now create thread by NtCreateThreadEx.\n");
		pFunc = GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtCreateThreadEx");
		if (pFunc == NULL)
		{
			printf("InjectCreateThread()-->GetProcAddress(\"NtCreateThreadEx\") Error %d\r\n", GetLastError());
			return FALSE;
		}
		((PFNTCREATETHREADEX)pFunc)(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			pRemoteBuf,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);
		if (hThread == NULL)
		{
			printf("InjectCreateThread()-->NtCreateThreadEx() Error: %d\r\n", GetLastError());
			return FALSE;
		}
		else
		{
			printf("InjectCreateThread()-->NtCreateThreadEx() Success,Thread Id:%ld\r\n", hThread);
		}
	}
	else                    // 2000, XP, Server2003
	{
		hThread = CreateRemoteThread(hProcess,
			NULL,
			0,
			pThreadProc,
			pRemoteBuf,
			0,
			NULL);
		if (hThread == NULL)
		{
			printf("InjectCreateThread()-->CreateRemoteThread() Error: %d\r\n", GetLastError());
			return FALSE;
		}
		else
		{
			printf("InjectCreateThread()-->CreateRemoteThread() Success,Thread Id:%ld\r\n", hThread);
		}
	}
	if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))
	{
		printf("InjectCreateThread() : WaitForSingleObject() Error: %d\r\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

typedef void*(__stdcall*LPFN_KernelBaseGetGlobalData)(void);
HANDLE MsicCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	OSVERSIONINFOEX stOSVersionInfoEx = { 0 };
	FARPROC pCreateRemoteThreadEx = NULL;
	LPFN_KernelBaseGetGlobalData pKernelBaseGetGlobalData = NULL;
	UCHAR *pCreateRemoteThread = NULL;
	UCHAR *pGlobalData = NULL;
	UCHAR *pMisc = NULL;
	HMODULE hKernelBase = NULL;
	HMODULE hKernel32 = NULL;
	HANDLE hNewThread = NULL;
	ULONG ulIndex = 0;
	WORD wCode = 0;
	do
	{
		stOSVersionInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		if (!GetVersionEx((OSVERSIONINFO*)&stOSVersionInfoEx))
		{
			break;
		}
		//vista以前的系统不存在这个问题
		if ((stOSVersionInfoEx.dwMajorVersion<6) || (GetCurrentProcess() == hProcess))
		{
			hNewThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, lpParameter, 0, &dwThreadId);
			if (dwThreadId)
			{
				printf("MsicCreateRemoteThread()-->CreateRemoteThread() Success,Thread Id:%08X\r\n", dwThreadId);
			}
			else
			{
				printf("MsicCreateRemoteThread()-->CreateRemoteThread() Error:%ld\r\n", GetLastError());
			}

			break;
		}
		if ((stOSVersionInfoEx.dwMajorVersion == 6) && (0 == stOSVersionInfoEx.dwMinorVersion))
		{
			//vista
			hKernel32 = LoadLibraryA("Kernel32.dll");
			pCreateRemoteThread = (UCHAR*)GetProcAddress(hKernel32, "CreateRemoteThread");
			for (ulIndex = 0; ulIndex<0x300; ulIndex += 1)
			{
				wCode = *((USHORT*)(pCreateRemoteThread + ulIndex));
#ifdef _WIN64
				if (0x3D80 == wCode)
				{
					pMisc = (*((ULONG*)(pCreateRemoteThread + ulIndex + 2))) + (pCreateRemoteThread + ulIndex + 7);
					break;
				}
#else
				if (0x1D38 == wCode)
				{
					pMisc = (UCHAR*)(*((ULONG*)(pCreateRemoteThread + ulIndex + 2)));
					break;
				}
#endif
			}
		}
		else if ((stOSVersionInfoEx.dwMajorVersion == 6) && (1 == stOSVersionInfoEx.dwMinorVersion))
		{
			//win7
			hKernelBase = LoadLibraryW(L"KernelBase.dll");
			if (NULL == hKernelBase)
			{
				break;
			}
			pKernelBaseGetGlobalData = (LPFN_KernelBaseGetGlobalData)GetProcAddress(hKernelBase, "KernelBaseGetGlobalData");
			printf("MsicCreateRemoteThread()-->KernelBaseGetGlobalData:%08X\r\n", pKernelBaseGetGlobalData);
			if (NULL == pKernelBaseGetGlobalData)
			{
				break;
			}
			pGlobalData = (UCHAR*)pKernelBaseGetGlobalData();
			if (NULL == pGlobalData)
			{
				break;
			}
#ifdef _WIN64
			pMisc = pGlobalData + 0x5C;
#else
			pMisc = pGlobalData + 0x30;//项目是Win32项目时会走这里
#endif
		}
		else
		{
			//手上的win8 Build 8250 没有session 隔离
		}
		//////////////////////////////////////////////////////////////////////////
		if (NULL == pMisc)
		{
			break;
		}
		printf("MsicCreateRemoteThread()-->pMisc: %08X\r\n", pMisc);
		//Patch
		*pMisc = 1;
		//xx
		hNewThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, lpParameter, 0, &dwThreadId);
		if (dwThreadId)
		{
			printf("MsicCreateRemoteThread()-->CreateRemoteThread() Success,Thread Id:%08X\r\n", dwThreadId);
		}
		else
		{
			printf("MsicCreateRemoteThread()-->CreateRemoteThread() Error:%ld\r\n", GetLastError());
		}
		//UnPatch
		*pMisc = 0;
	} while (FALSE);
	if (NULL != hKernelBase)
	{
		printf("MsicCreateRemoteThread()-->hKernelBase:%08X\r\n", hKernelBase);
		FreeLibrary(hKernelBase);
		hKernelBase = NULL;
	}
	return hNewThread;
}

void HookGetMessage()
{
	HOOKPROC hp;
	//SetWindowsHookEx(WH_GETMESSAGE,hp,)
}