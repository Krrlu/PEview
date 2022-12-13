#include <iostream>
#include "BaseFileHeader.h"


void errorreturn(int i) {
	switch (i) {
	case -1:
		printf("Error, cannot open the file");
		exit(-1);
		break;

	case -2:
		printf("Error, not a PE file");
		exit(-2);
		break;

	}
}

void pmachinetype(WORD i) {
	switch (i) {
	case IMAGE_FILE_MACHINE_UNKNOWN:
		printf("Machine: Unknown\n");
		break;

	case IMAGE_FILE_MACHINE_AMD64:
		printf("Machine: x64\n");
		break;

	case IMAGE_FILE_MACHINE_ARM64:
	case IMAGE_FILE_MACHINE_ARMNT:
	case IMAGE_FILE_MACHINE_ARM:
		printf("Machine: ARM\n");
		break;

	case IMAGE_FILE_MACHINE_I386:
		printf("Machine: Intel 386\n");
		break;

	case IMAGE_FILE_MACHINE_IA64:
		printf("Machine: Intel Itanium processor family\n");
		break;

	case IMAGE_FILE_MACHINE_RISCV32:
	case IMAGE_FILE_MACHINE_RISCV64:
	case IMAGE_FILE_MACHINE_RISCV128:

		printf("Machine: RISC-V\n");
		break;

	default:
		printf("Machine: Other\n");
	}



}

void printtime(time_t stamp) {
	char buffer[17];
	std::tm* t = gmtime(&stamp);

	sprintf(buffer, "Date: %d/%d/%d",t->tm_mon+1, t->tm_mday, 1900 + t->tm_year);
	printf("%s\n", buffer);
}

void fileHeader(LPCSTR fileLocaion) {
	HANDLE fileHandle, mappingHandle;
	LPVOID mapPointer;
	IMAGE_FILE_HEADER coffheader;
	DWORD AddressOfEntryPoint;
	ULONGLONG ImageBase;
	
	BYTE* opHeader; // pointer of optional header
	int bit = 1;   // 1 for 32 bit , 2 for 64 bit, determine by optional header magic number
				   // Used as a multiplicity of number, because size of some fields is double for 64bit
	
	
	fileHandle = CreateFileA(fileLocaion, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		errorreturn(-1);
	}

	mappingHandle = CreateFileMappingA(fileHandle,NULL, PAGE_READONLY,0,0,NULL);
	if (mappingHandle == NULL) {
		errorreturn(-1);
	}

	mapPointer = MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0);
	if (mapPointer == NULL) {
		errorreturn(-1);
	}
	if (*((WORD*)mapPointer) != IMAGE_DOS_SIGNATURE){
		errorreturn(-2);
	}
	int offsetPE = *(DWORD*)((BYTE*)mapPointer + 0x3c);
	if (*(DWORD*)((BYTE*)mapPointer + offsetPE) != IMAGE_NT_SIGNATURE) {
		errorreturn(-2);
	}
	coffheader = *(IMAGE_FILE_HEADER*)((BYTE*)mapPointer + offsetPE + 4);

	pmachinetype(coffheader.Machine);
	printtime(coffheader.TimeDateStamp);

	opHeader = (BYTE*)mapPointer + offsetPE + 24;
	bit += (*(WORD*)(opHeader) == 0x20b); // bit == 2 if it is PE32+ 

	if (coffheader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		printf("File is %d-bit executable\n",32*bit);
	}

	if (coffheader.Characteristics & IMAGE_FILE_DLL) {
		printf("File is a dynamic-link library\n");
	}

	if (coffheader.Characteristics & IMAGE_FILE_SYSTEM) {
		printf("File is a system file\n");
	}
	AddressOfEntryPoint = *(DWORD*)(opHeader + 16);

	if (bit == 1) {
		ImageBase = *(DWORD*)(opHeader + 28);
	}
	else {
		ImageBase = *(ULONGLONG*)(opHeader + 24);
	}
	//printf("%x\n", ImageBase);
}

