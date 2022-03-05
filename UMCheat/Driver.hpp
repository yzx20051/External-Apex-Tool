#ifndef _DRIVER_HPP
#define _DRIVER_HPP

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include <mutex>
#include <TlHelp32.h>



typedef struct _NULL_MEMORY
{
	void* buffer_address;
	UINT_PTR address;
	ULONGLONG size;
	ULONG pid;
	BOOLEAN write;
	BOOLEAN read;
	BOOLEAN req_base;
	void* output;
	const char* module_name;
	ULONG64 base_address;
}NULL_MEMORY;
/***********************************************根据游戏自定义的变量*********************************************************/
static std::uint32_t pId = 0; //游戏PID
static uintptr_t gBase = 0, gname;
static uintptr_t uBase = 0;
static int width, height;


/***********************************************根据游戏自定义的变量*********************************************************/
struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}
	}
};

using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

static std::uint32_t __fastcall get_process_id(std::string_view process_name)
{
	PROCESSENTRY32 processentry;
	const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return NULL;

	processentry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE)
	{
		if (process_name.compare(processentry.szExeFile) == NULL)
		{
			return processentry.th32ProcessID;
		}
	}
	return NULL;
}

template<typename ... A>
uint64_t __fastcall call_hook(const A ... arguments)
{
	void* hooked_func = GetProcAddress(LoadLibrary("win32u.dll"), "NtOpenCompositionSurfaceSectionInfo"); // NtOpenCompositionSurfaceSectionInfo

	auto func = static_cast<uint64_t(_stdcall*)(A...)>(hooked_func);

	return func(arguments ...);
}



static ULONG64 __fastcall get_module_base_address(const char* moduleName)
{

	NULL_MEMORY instructions = { 0 };
	instructions.pid = pId;
	instructions.req_base = TRUE;
	instructions.read = FALSE;
	instructions.write = FALSE;
	instructions.module_name = moduleName;
	call_hook(&instructions);

	ULONG64 base = NULL;
	base = instructions.base_address;
	return base;
}

template <class T>
T __fastcall Read(UINT_PTR ReadAddress)
{
	T response{};
	NULL_MEMORY instructions;
	instructions.pid = pId;
	instructions.size = sizeof(T);
	instructions.address = ReadAddress;
	instructions.read = TRUE;
	instructions.write = FALSE;
	instructions.req_base = FALSE;
	instructions.output = &response;
	call_hook(&instructions);

	return response;
}

template <typename Type>
Type ReadChain(uint64_t address, std::vector<uint64_t> chain) {
	uint64_t current = address;
	for (int i = 0; i < chain.size() - 1; i++) {
		current = Read<uint64_t>(current + chain[i]);
	}
	return Read<Type>(current + chain[chain.size() - 1]);
}

static bool __fastcall WriteVirtualMemoryRaw(UINT_PTR WriteAddress, UINT_PTR SourceAddress, SIZE_T WriteSize);

template<typename S>
bool __fastcall Write(UINT_PTR WriteAddress, const S& value)
{
	return WriteVirtualMemoryRaw(WriteAddress, (UINT_PTR)&value, sizeof(S));
}

bool __fastcall WriteVirtualMemoryRaw(UINT_PTR WriteAddress, UINT_PTR SourceAddress, SIZE_T WriteSize)
{
	NULL_MEMORY instructions;
	instructions.address = WriteAddress;
	instructions.pid = pId;
	instructions.write = TRUE;
	instructions.read = FALSE;
	instructions.req_base = FALSE;
	instructions.buffer_address = (void*)SourceAddress;
	instructions.size = WriteSize;

	call_hook(&instructions);

	return true;
}




#endif