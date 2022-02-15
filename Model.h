#pragma once
#include <crtdefs.h>
#include <ntdef.h>
#include <wdm.h>

#define bufferSize 512
#define nameSize 2048

unsigned recordsCount = 0;
unsigned configUpdated = 0;
//unsigned configReadyToRead = 0;

enum Rights {
	errorOrNotFound = 0,
	noReadNoWrite = 1,
	onlyRead = 2,
	onlyWrite = 3,
	readAndWrite = 4
};

struct Record {
	char ProcessName[nameSize];
	unsigned pNameSize;

	char Filename[nameSize];
	unsigned fNameSize;

	enum Rights right;
} Records[10];

void parseConfigData(char* data) {
	recordsCount = 0;

	const unsigned count = *data++ - '0';
	while ((*data == '\n') || (*data == '\r')) ++data;

	for(unsigned i = 0; i < count; ++i) {
		struct Record* tmpRecord = &(Records[recordsCount]);
		tmpRecord->pNameSize = 0;
		tmpRecord->fNameSize = 0;

		/* Process name. */
		for (; *data != ' ' && *data != '.'; data++)
			tmpRecord->ProcessName[tmpRecord->pNameSize++] = *data;
		tmpRecord->ProcessName[tmpRecord->pNameSize] = 0;
		for (; *data != ' '; ++data);
		data++;

		/* File name. */
		for (; *data != ' ' && *data != '.'; data++)
			tmpRecord->Filename[tmpRecord->fNameSize++] = *data;
		tmpRecord->Filename[tmpRecord->fNameSize] = 0;
		for (; *data != ' '; ++data);
		data++;

		/* Reading permission. */
		if (*data == 'r') {
			if (*(data + 1) == 'w') {
				tmpRecord->right = readAndWrite;
				DbgPrint("[Found] Process: '%s', file: '%s'| Reading and writing.\n",
					tmpRecord->ProcessName, tmpRecord->Filename);
			}
			else {
				tmpRecord->right = onlyRead;
				DbgPrint("[Found] Process: '%s', file: '%s'| Reading.\n",
					tmpRecord->ProcessName, tmpRecord->Filename);
			}
		}
		else {
			if (*(data + 1) == 'w') {
				tmpRecord->right = onlyWrite;
				DbgPrint("[Found] Process: '%s', file: '%s'| Writing.\n",
					tmpRecord->ProcessName, tmpRecord->Filename);
			}
			else {
				tmpRecord->right = noReadNoWrite;
				DbgPrint("[Found] Process: '%s', file: '%s'| No reading, no writing.\n",
					tmpRecord->ProcessName, tmpRecord->Filename);
			}
		}

		for (; (*data != '\n') && (*data != '\r') && (*data != 0); ++data);
		while ((*data == '\n') || (*data == '\r')) ++data;
		recordsCount++;
	}
}

void readConfig(WCHAR* filename) {
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING uniName;

	RtlInitUnicodeString(&uniName, filename);
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	HANDLE handle;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK ioStatusBlock;

	LARGE_INTEGER byteOffset;
	ntstatus = ZwCreateFile(&handle,
		GENERIC_READ,
		&objAttr, &ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	CHAR buffer[bufferSize] = { 0 };
	if (NT_SUCCESS(ntstatus))
	{
		DbgPrint("[+] File opened successfully.\n");
		byteOffset.LowPart = byteOffset.HighPart = 0;

		ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
			buffer, bufferSize, &byteOffset, NULL);

		if (NT_SUCCESS(ntstatus))
			parseConfigData(buffer);
		ZwClose(handle);
	}
	else {
		DbgPrint("[-] End of the file or another error:\n");
		DbgPrint("[-] Error: %x.\n", ntstatus);
	}
}

void cutPathAndExtension(const char* const from, char* to) {
	if (from == NULL || to == NULL) return;
	char* end = from;
	for (; *end != 0; ++end);

	char* begin = end;
	for (; *begin != '\\' && begin != from; --begin);
	if (*begin == '\\') begin++;

	char* tmp = end;
	for (; *tmp != '.' && tmp != begin; --tmp);
	if (*tmp == '.')
		end = tmp;

	tmp = begin;
	for (; tmp != end; ++tmp)
		*(to++) = *tmp;
	*to = 0;
}

enum Rights findRecord(const char* const processName, const char* const filename) {
	for (unsigned i = 0; i < recordsCount; ++i) {
		const struct Record* tmpRecord = &(Records[i]);
		
		if (strcmp(tmpRecord->ProcessName, processName) == 0 &&
			strcmp(tmpRecord->Filename, filename) == 0)
			return tmpRecord->right;	
	}

	return errorOrNotFound;
}