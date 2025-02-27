#pragma once

#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <vector>

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

using pRtlInitUnicodeString = NTSTATUS(NTAPI*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
using pLdrLoadDll = NTSTATUS(NTAPI*)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

// ä÷êîêÈåæ
DWORD GetProcessIdByProcessName(const std::wstring& processName);
