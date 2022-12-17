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

void printsubsystem(WORD i) {
	switch (i) {
	case IMAGE_SUBSYSTEM_UNKNOWN:
		printf("Subsystem: Unknown subsystem\n");
		break;

	case  IMAGE_SUBSYSTEM_NATIVE:
		printf("Subsystem: Doesn't require a subsystem\n");
		break;

	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		printf("Subsystem: Windows GUI subsystem\n");
		break;

	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		printf("Subsystem: Windows character subsystem\n");
		break;

	case IMAGE_SUBSYSTEM_OS2_CUI:
		printf("Subsystem: OS/2 character subsystem\n");
		break;

	case IMAGE_SUBSYSTEM_POSIX_CUI:
		printf("Subsystem: Posix character subsystem\n");
		break;

	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		printf("Subsystem: Win9x driver\n");
		break;

	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		printf("Subsystem: Windows CE subsystem\n");
		break;

	default:
		printf("Subsystem: Other\n");
	}

}

void printdatadirectories(PIMAGE_DATA_DIRECTORY data_directory) {
	printf("                       RVA SIZE\n");
	printf("Export Table:            %x   %x\n", data_directory[0].VirtualAddress, data_directory[0].Size);
	printf("Import Table:            %x   %x\n", data_directory[1].VirtualAddress, data_directory[1].Size);
	printf("Resource Table:          %x   %x\n", data_directory[2].VirtualAddress, data_directory[2].Size);
	printf("Exception Table:         %x   %x\n", data_directory[3].VirtualAddress, data_directory[3].Size);
	printf("Certificate Table:       %x   %x\n", data_directory[4].VirtualAddress, data_directory[4].Size);
	printf("Base Relocation Table:   %x   %x\n", data_directory[5].VirtualAddress, data_directory[5].Size);
	printf("Debug:                   %x   %x\n", data_directory[6].VirtualAddress, data_directory[6].Size);
	printf("Architecture:            %x   %x\n", data_directory[7].VirtualAddress, data_directory[7].Size);
	printf("Global Ptr:              %x   %x\n", data_directory[8].VirtualAddress, data_directory[8].Size);
	printf("TLS Table:               %x   %x\n", data_directory[9].VirtualAddress, data_directory[9].Size);
	printf("Load Config Table:       %x   %x\n", data_directory[10].VirtualAddress, data_directory[10].Size);
	printf("Bound Import:            %x   %x\n", data_directory[11].VirtualAddress, data_directory[11].Size);
	printf("IAT:                     %x   %x\n", data_directory[12].VirtualAddress, data_directory[12].Size);
	printf("Delay Import Descriptor: %x   %x\n", data_directory[13].VirtualAddress, data_directory[13].Size);
	printf("CLR Runtime Header:      %x   %x\n", data_directory[14].VirtualAddress, data_directory[14].Size);
	printf("Reserved:                %x   %x\n", data_directory[15].VirtualAddress, data_directory[15].Size);


	
}

void fileHeader(LPCSTR fileLocaion) {
	HANDLE fileHandle, mappingHandle;
	LPVOID mapPointer;
	IMAGE_FILE_HEADER coffheader;
	DWORD AddressOfEntryPoint;
	ULONGLONG ImageBase;
	IMAGE_DATA_DIRECTORY data_directory[16];
	
	BYTE* opHeader; // pointer of optional header
	boolean pe32plus = 0;   // 0 for 32 bit , 1 for 64 bit, determine by optional header magic number
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


	opHeader = (BYTE*)mapPointer + offsetPE + 24;
	pe32plus = (*(WORD*)(opHeader) == 0x20b); // bit == 1 if it is PE32+ 

	if (coffheader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		printf("File is %d-bit executable\n",32*(pe32plus + 1));
	}

	if (coffheader.Characteristics & IMAGE_FILE_DLL) {
		printf("File is a dynamic-link library\n");
	}

	if (coffheader.Characteristics & IMAGE_FILE_SYSTEM) {
		printf("File is a system file\n");
	}
	AddressOfEntryPoint = *(DWORD*)(opHeader + 16);

	if (!pe32plus) {
		ImageBase = *(DWORD*)(opHeader + 28);
	}
	else {
		ImageBase = *(ULONGLONG*)(opHeader + 24);
	}
	

	//base offset 96 bits, each table is 8 bits, 16 is offfet for 64 bits program
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		data_directory[i] = *(PIMAGE_DATA_DIRECTORY)(opHeader + i * 8 + 96 + 16 * (pe32plus));
		// bit = 2 if program is 64 bits
	}

	BYTE* SectionTable = (opHeader + coffheader.SizeOfOptionalHeader); // start adress if SectionTable
	
	

	printsubsystem(*(WORD*)(opHeader + 68));
	pmachinetype(coffheader.Machine);
	printtime(coffheader.TimeDateStamp);
	printdatadirectories(data_directory);
}

