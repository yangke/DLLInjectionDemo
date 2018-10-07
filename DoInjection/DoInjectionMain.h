#pragma once
#pragma warning(disable: 4996)
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL IsVistaOrLater();
BOOL InjectProcess();
BOOL InjectCreateProcess();
void HookGetMessage();
BOOL InjectCreateThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf);
HANDLE MsicCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);

typedef void*(__stdcall*LPFN_KernelBaseGetGlobalData)(void);
typedef DWORD(WINAPI *PFNTCREATETHREADEX)
(
	PHANDLE                 ThreadHandle,
	ACCESS_MASK             DesiredAccess,
	LPVOID                  ObjectAttributes,
	HANDLE                  ProcessHandle,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	BOOL                    CreateSuspended,
	DWORD                   dwStackSize,
	DWORD                   dw1,
	DWORD                   dw2,
	LPVOID                  Unknown
	);