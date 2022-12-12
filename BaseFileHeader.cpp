#include <iostream>
#include "BaseFileHeader.h"


void errorleave(int i) {
	switch (i) {
	case -1:
		printf("Error, cannot open the file map");
		exit(-1);
		break;

	}
}

void fileHeader(LPCSTR fileLocaion) {
	HANDLE fileHandle, mappingHandle;
	LPVOID mapPointer;

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
	printf("%x", *((WORD*)mapPointer) == IMAGE_DOS_SIGNATURE);

}

