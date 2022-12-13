#include <windows.h>
#include <iostream>

#define IMAGE_FILE_MACHINE_RISCV32 0x5032
#define IMAGE_FILE_MACHINE_RISCV64 0x5064
#define IMAGE_FILE_MACHINE_RISCV128 0x5128

void fileHeader(LPCSTR fileLocaion);
