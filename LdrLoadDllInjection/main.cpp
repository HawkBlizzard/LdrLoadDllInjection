// main.cpp
#include "injector.h"

// エントリポイント
int wmain(int argc, wchar_t* argv[]) {

    /* 逆アセンブル
    void func() {
	    UNICODE_STRING uStr;
	    RtlInitUnicodeString(&uStr, L"C:\\Payload\\Test.dll");
	    HANDLE moduleHandle = nullptr;
	    NTSTATUS status = LdrLoadDll(NULL, 0, &uStr, &moduleHandle);
     }
    
    00007FF70A3D1060 | 48:83EC 48               | sub rsp,48
    00007FF70A3D1064 | 48:8B05 951F0000         | mov rax,qword ptr ds:[7FF70A3D3000]
    00007FF70A3D106B | 48:33C4                  | xor rax,rsp
    00007FF70A3D106E | 48:894424 38             | mov qword ptr ss:[rsp+38],rax
    00007FF70A3D1073 | 48:8D15 26120000         | lea rdx,qword ptr ds:[7FF70A3D22A0]
    00007FF70A3D107A | 48:8D4C24 28             | lea rcx,qword ptr ss:[rsp+28]
    00007FF70A3D107F | FF15 EB250000            | call qword ptr ds:[<&RtlInitUnicodeString>]
    00007FF70A3D1085 | 4C:8D4C24 20             | lea r9,qword ptr ss:[rsp+20]
    00007FF70A3D108A | 48:C74424 20 00000000    | mov qword ptr ss:[rsp+20],0
    00007FF70A3D1093 | 4C:8D4424 28             | lea r8,qword ptr ss:[rsp+28]
    00007FF70A3D1098 | 33D2                     | xor edx,edx
    00007FF70A3D109A | 33C9                     | xor ecx,ecx
    00007FF70A3D109C | FF15 D6250000            | call qword ptr ds:[<&LdrLoadDll>]
    00007FF70A3D10A2 | 33C0                     | xor eax,eax
    00007FF70A3D10A4 | 48:8B4C24 38             | mov rcx,qword ptr ss:[rsp+38]
    00007FF70A3D10A9 | 48:33CC                  | xor rcx,rsp
    00007FF70A3D10AC | E8 1F000000              | call ldrloaddllinjection.7FF70A3D10D0
    00007FF70A3D10B1 | 48:83C4 48               | add rsp,48
    00007FF70A3D10B5 | C3                       | ret
    */

    std::vector<BYTE> ldrLoadDllStub{
        0x48, 0x83, 0xEC, 0x48, // sub rsp,48
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, [DLLパスのアドレス]
        0x48, 0x8D, 0x4C, 0x24, 0x28, // lea rcx,[rsp+28]
        0x48, 0xBF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rdi, RtlInitUnicodeString
        0xFF, 0xD7, // call rdi
        0x4C, 0x8D, 0x4C, 0x24, 0x20, // lea r9,[rsp+20]
        0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // mov qword ptr [rsp+20],00000000
        0x4C, 0x8D, 0x44, 0x24, 0x28, // lea r8,[rsp+28]
        0x33, 0xD2, // xor edx,edx
        0x33, 0xC9, // xor ecx,ecx
        0x48, 0xBF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rdi, LdrLoadDll
        0xFF, 0xD7, // call rdi
        0x33, 0xC0, // xor eax,eax
        0x48, 0x83, 0xC4, 0x48, // add rsp,48
        0xC3 // ret 
    };

    SIZE_T dllPathOffset = 6;
    SIZE_T unicodeStringFuncOffset = 21;
    SIZE_T ldrLoadDllFuncOffset = 56;

    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << "[プロセス名] [DLLパス]" << std::endl;
        return 1;
    }

    std::wstring processName = argv[1];
    std::wstring dllPath = argv[2];

    // DLLパスサイズを計算
    SIZE_T dllPathSize = (dllPath.size() + 1) * sizeof(wchar_t);

    // プロセス名からプロセスIDを取得
    DWORD processId = GetProcessIdByProcessName(processName);

    // プロセスハンドルを取得
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    // DLLパスをターゲットプロセスに書き込む
    LPVOID dllPathMemory = VirtualAllocEx(processHandle, nullptr, dllPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(processHandle, dllPathMemory, dllPath.c_str(), dllPathSize, NULL);

    // 関数アドレスを取得
    pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
    pLdrLoadDll LdrLoadDll = (pLdrLoadDll)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "LdrLoadDll");

    // スタブにアドレスを書き込む
    RtlMoveMemory(&ldrLoadDllStub[dllPathOffset], &dllPathMemory, sizeof(DWORD_PTR));
    RtlMoveMemory(&ldrLoadDllStub[unicodeStringFuncOffset], &RtlInitUnicodeString, sizeof(DWORD_PTR));
    RtlMoveMemory(&ldrLoadDllStub[ldrLoadDllFuncOffset], &LdrLoadDll, sizeof(DWORD_PTR));

    // スタブをリモートプロセスに書き込む
    LPVOID loadLibraryStubMemory = VirtualAllocEx(processHandle, nullptr, ldrLoadDllStub.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processHandle, loadLibraryStubMemory, ldrLoadDllStub.data(), ldrLoadDllStub.size(), nullptr);

    // リモートスレッドを作成してスタブを実行
    CreateRemoteThread(processHandle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryStubMemory), nullptr, 0, nullptr);

    return 0;
}