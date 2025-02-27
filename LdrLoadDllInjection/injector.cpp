#include "injector.h"

// �v���Z�X������v���Z�XID���擾
DWORD GetProcessIdByProcessName(const std::wstring& processName) {

    // �v���Z�X�̃X�i�b�v�V���b�g���擾
    HANDLE snapProcessHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W) };

    // �ŏ��̃v���Z�X�����擾
    BOOL hasNextProcess = Process32First(snapProcessHandle, &processEntry);

    // �X�i�b�v�V���b�g�̃t�@�C�����ƃ^�[�Q�b�g�v���Z�X�����r
    for (; hasNextProcess; hasNextProcess = Process32Next(snapProcessHandle, &processEntry)) {
        if (processName == processEntry.szExeFile) {
            return processEntry.th32ProcessID;
        }
    }

    return 0;
}