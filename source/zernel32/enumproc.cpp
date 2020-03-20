#include "stdafx.h"
#include <windows.h>
#include "kernel32.h"
#include "winternl.h"

typedef NTSTATUS(NTAPI * PNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L

static inline BOOL set_ntstatus(NTSTATUS status)
{
    if (status) SetLastError(DWORD(status));
    return !status;
}

extern "C" BOOL WINAPI K32EnumProcesses(DWORD *lpdwProcessIDs, DWORD cb, DWORD *lpcbUsed)
{
    HMODULE ntdll = LoadLibrary("ntdll.dll");
    PNtQuerySystemInformation NtQuerySystemInformation = PNtQuerySystemInformation(GetProcAddress(ntdll, "NtQuerySystemInformation"));

    SYSTEM_PROCESS_INFORMATION *spi;
    ULONG size = 0x4000;
    void *buf = NULL;
    NTSTATUS status;

    do {
        size *= 2;
        HeapFree(GetProcessHeap(), 0, buf);
        buf = HeapAlloc(GetProcessHeap(), 0, size);
        if (!buf)
            return FALSE;

        status = NtQuerySystemInformation(SystemProcessInformation, buf, size, NULL);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!set_ntstatus(status))
    {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    spi = (SYSTEM_PROCESS_INFORMATION*)buf;

    for (*lpcbUsed = 0; cb >= sizeof(DWORD); cb -= sizeof(DWORD))
    {
        *lpdwProcessIDs++ = HandleToUlong(spi->UniqueProcessId);
        *lpcbUsed += sizeof(DWORD);

        if (spi->NextEntryOffset == 0)
            break;

        spi = (SYSTEM_PROCESS_INFORMATION *)(((PCHAR)spi) + spi->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return TRUE;
}