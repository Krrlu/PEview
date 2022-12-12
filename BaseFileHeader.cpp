#include <iostream>
#include "BaseFileHeader.h"


void errorleave(int i) {
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

	case 0x5032:
	case 0x5064:
	case 0x5128:

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
	printf("%s", buffer);
}

void fileHeader(LPCSTR fileLocaion) {
	HANDLE fileHandle, mappingHandle;
	LPVOID mapPointer;
	IMAGE_FILE_HEADER Imagefh;

	fileHandle = CreateFileA(fileLocaion, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		errorleave(-1);
	}

	mappingHandle = CreateFileMappingA(fileHandle,NULL, PAGE_READONLY,0,0,NULL);
	if (mappingHandle == NULL) {
		errorleave(-1);
	}

	mapPointer = MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0);
	if (mapPointer == NULL) {
		errorleave(-1);
	}
	if (*((WORD*)mapPointer) != IMAGE_DOS_SIGNATURE){
		errorleave(-2);
	}
	int offsetPE = *(DWORD*)((BYTE*)mapPointer + 0x3c);
	if (*(DWORD*)((BYTE*)mapPointer + offsetPE) != IMAGE_NT_SIGNATURE) {
		errorleave(-2);
	}
	Imagefh = *(IMAGE_FILE_HEADER*)((BYTE*)mapPointer + offsetPE + 4);
	pmachinetype(Imagefh.Machine);
	printtime(Imagefh.TimeDateStamp);
}

