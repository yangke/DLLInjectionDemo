# DLLInjectionDemo
This repository is a demo of dll injection. 
It demostates how to hook and inject data during the DragDrop process in explorer.exe  implemented by wine.

Use MS Visual Studio 2017 to create a solution and add-in the following project.
Then build the total solution under release mode(debug mode may cause error currently).

## DoInjection

* This project is created as normal Console Application.

This program create(`CreateProcess`) the target process by name string(e.g "explorer.exe", hard coded in DoInjection), 
As we need the `MfcHookApi.dll` load by the remote target process `explorer.exe`,
the dll name `MfcHookApi.dll` passed to `LoadLibraryA`(in kernel32.dll) must be allocated at the virtual address of process `explorer.exe`
Tips：`MfcHookApi.dll` contains the substitute for WINAPI:`DispatchMessageW/A` and perform the real hook&inject operation. 
So `DoInjection` use the core API `VirtualAllocEx` and `WriteProcessMemory` to write the string to the space of `explorer.exe`,
and it uses the process handle of `explorer.exe` and the address of `LoadLibraryA` to create a remote thread which loads and initiates the `MfcHookApi.dll` to the space of `explorer.exe`.

## DoWin32Test

* This project is created as  Win32 MFC Application.

This MFC window program is used as an injection target when running DoInjection in Windows System(Win7 is OK,other versions need more test).

## MfcHookApi

* This project is created as  MFC dll Application.

When this MFC dll is loaded(with the target process`explorer.exe`), its `CMfcHookApiApp::InitInstance` function will be triggered.
and it will perform the core call `SetHookCreateWindowEx(GetModuleHandle(NULL));` to hook CreateWindowExW/A.
Specificially, it use 
```
HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
```
 to get the snapshot of all system processes,
and find the process handle of the process with the correct `pcProsessName`.

Then it loads the `user32.dll` and modify the jump instruction located at original `CreateWindowExW/A`.
Note that we have to gurantee that the hook must be cleared when performing interception operations.
So, we must clear and rehook before and and after performing the following core opreations.

### Goal OPERATIONS
Between the above-mentioned covers, we can safely perform the core business.
By adding judgement code in the substitute of `CreateWindowA`(which is `HookCreateWindowExA` function in `MfcHookApi` project), we can intercept call to `CreateWindowA` when creating specific window "" during drag and drop.
At this point, we hook the DispatchMessageW and judge the condition of the last drop state.
Wine code has provide the exact code of this judgement process. The judgement process is from the last message dispatching(`DispatchMessageW`) to `ISFDropTarget\_Drop`.
As we already figure out this path, here we just make a retro version.
The core conditions and details are implemented in `inspect_before` function.
```
void inspect_before(MSG* msg)
{
	WCHAR temp[256];
	GetClassName(msg->hwnd, temp, 256);
	if (0 == wcscmp(_T("WineDragDropTracker32"), temp))
	{		
		TrackerWindowInfo * info = (TrackerWindowInfo *)GetWindowLongPtrA(msg->hwnd, 0);
		if (info)
		{
			if (info->curDragTarget && info->returnValue==0)
			{
				HRESULT _hr=IDropSource_QueryContinueDrag(info->dropSource, info->escPressed, info->dwKeyState);
				if (_hr == DRAGDROP_S_DROP)
				{
					//access and tamper the string field "->sPathTarget"
```
Trial and error is unavoidable for declaration of correct data structures, but it is straight forward as a whole.

The so called "hooking" here is just a kind of code tampering, not the classic hook, as the classic hook usually use `SetWindowsHookEx` function, and it intercepts limited predefined windows functions
The target program is responsible for recover it.
The following code illustrate the classic windows hooking technique(but we doesn't use here).

```
//An empty hook function.
LRESULT WINAPI HookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(hHook, nCode, wParam, lParam);
}
//Install or uninstall an empty hook(ProcessID=NULL：uninstall).
extern "C" __declspec(dllexport) void InstallHook4Api(HWND hwnd)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	if (hwnd)
		hHook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)HookProc, hinstDll, GetWindowThreadProcessId(hwnd, &TargetPid));
	else
	{
		if (hHook)
			UnhookWindowsHookEx(hHook);
	}
}
```
