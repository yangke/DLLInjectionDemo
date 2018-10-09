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
and it will perform the core call `SetHookCreateWindowEx(GetModuleHandle(NULL));` to hook `CreateWindowExW/A`.
Specificially, it use 
```
HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
```
 to get the snapshot of all system processes,
and find the process handle of the process with the correct `pcProsessName`.

Then it loads the `user32.dll` and modify the jump instruction located at original `CreateWindowExW/A`.
Note that we have to gurantee that the hook must be cleared when performing interception operations.
So, we must clear hook and rehook before and and after the core functional routine.

### Goal OPERATIONS
With the above-mentioned covers, we can safely do the core business.
Now that the call to `CreateWindowA` has been redirected to function `HookCreateWindowExA`,
what we need to do in `HookCreateWindowExA` is to add judgement code to make sure the specific window "WineDragDropTracker32" is created.
The window used for drag-drop tracking in wine has this unique class name.
Then we intercept and monitor `DispatchMessageW`.
We need to locate the last dispatched message of the drop process and pin-point the position before calling `ISFDropTarget\_Drop`(in wine).
Because the fix for `ISFDropTarget\_Drop` use `This->sPathTarget` without checking it validity.
```
static HRESULT WINAPI
ISFDropTarget_Drop (IDropTarget * iface, IDataObject * pDataObject,
                    DWORD dwKeyState, POINTL pt, DWORD * pdwEffect)
{
    IGenericSFImpl *This = impl_from_IDropTarget(iface);
	...
	for (i = 0; i < pidaShellIDList->cidl; i++) {
		...
        switch (*pdwEffect) {
			case DROPEFFECT_MOVE:		
				if (wszSourcePath[0]!='\0'&& This->sPathTarget)
				{
					if (strcmpW(wszSourcePath, This->sPathTarget))
					{
						SHFILEOPSTRUCTW fileOp;
						WCHAR srcPath[MAX_PATH];
						WCHAR *wszPathsList;

						lstrcpynW(srcPath, wszSourcePath, MAX_PATH);
						
						PathAddBackslashW(srcPath);
						wszPathsList = build_paths_list(srcPath, 1, (LPCITEMIDLIST*)&apidl[i]);
						ZeroMemory(&fileOp, sizeof(fileOp));
						fileOp.hwnd = GetActiveWindow();
						fileOp.wFunc = FO_MOVE;
						fileOp.pFrom = wszPathsList;
						fileOp.pTo = This->sPathTarget;//without length check
						fileOp.fFlags = FOF_NOCONFIRMATION;
						hr = (SHFileOperationW(&fileOp)==0 ? S_OK : E_FAIL);
					}
				}
				else
					hr = E_OUTOFMEMORY;
					break;
			case DROPEFFECT_COPY:
			    //This->sPathTarget without length or NULL check
				ISFHelper_CopyItems(&This->ISFHelper_iface, psfSourceFolder, pidaShellIDList->cidl, (LPCITEMIDLIST*)apidl);
				break;
		...
```
Wine code has provide the exact code of this judgement, from message dispatching(`DispatchMessageW`) and all the way through `ISFDropTarget\_Drop`.
The following graph shows the three key opreation of the drop process. What we talk here is the intercepting of the last(right hand) path.
![Three key operations of drop process(set target path data,check keyboard state, do real process)][docs/pictures/three_step_of_drop.pdf]
This path can be obtained by manually debugging wine code(as our attacking target is wine).
Make a retro version of this process and change the data just before the last message dispatching, then a successful data tampering is performed.
See `inspect_before` function for core judgement and data tampering logics of this process.
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
