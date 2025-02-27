#include "injector.h"

// プロセス名からプロセスIDを取得
DWORD GetProcessIdByProcessName(const std::wstring& processName) {

    // プロセスのスナップショットを取得
    HANDLE snapProcessHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W) };

    // 最初のプロセス情報を取得
    BOOL hasNextProcess = Process32First(snapProcessHandle, &processEntry);

    // スナップショットのファイル名とターゲットプロセス名を比較
    for (; hasNextProcess; hasNextProcess = Process32Next(snapProcessHandle, &processEntry)) {
        if (processName == processEntry.szExeFile) {
            return processEntry.th32ProcessID;
        }
    }

    return 0;
}