#include "Validator.h"

#include <windows.h>
#include <iostream>
#include <Psapi.h>
#include "LDasm.h"
#pragma comment( lib, "psapi.lib" )


#define NtCurrentThread ((HANDLE)-2)
typedef unsigned int(NTAPI* lpRtlComputeCrc32)(DWORD dwInitial, void * pData, int iLen);
static lpRtlComputeCrc32 RtlComputeCrc32 = nullptr;


inline bool IsLegitReturnAddressEBP(DWORD dwFunctionAddress, DWORD dwLowAddress, DWORD dwHighAddress)
{
	DWORD dwReturnAddress = 0;

	__asm {pushad}
	__asm {mov eax, dword ptr ds : [ebp + 4]}
	__asm {mov dwReturnAddress, eax}
	__asm {popad};

	return ((dwReturnAddress >= dwLowAddress) && (dwReturnAddress <= dwHighAddress));
}

inline DWORD GetChecksum(PVOID pFunction, DWORD dwLength)
{
	DWORD checksum = 0;
	__try { checksum = RtlComputeCrc32(0, pFunction, dwLength); }
	__except (1) { return 1; };
	return checksum;
}

inline int GetBreakpointCount(DWORD dwStartAddress, DWORD dwLength)
{
	int count = 0;
	DWORD dwCurrentAddress = dwStartAddress;
	while (dwStartAddress + dwLength > dwCurrentAddress) {
		if (*(BYTE *)dwCurrentAddress == 0xCC)
			count++;

		dwCurrentAddress++;
	}

	return count;
}


int FunctionValidator::CFunctionValidator::ValidityFunction(LPVOID pFunction, int * piBpCount, int * piFunctionSize, DWORD * pdwChecksum)
{
	auto dwFunctionAddress = reinterpret_cast<DWORD>(pFunction);


	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(reinterpret_cast<LPCVOID>(dwFunctionAddress), &mbi, sizeof(mbi)))
		return VQUERY_FAIL;

	if (mbi.Protect == PAGE_NOACCESS)
		return NOACCESS_EXCEPTION;

	if (mbi.Protect & PAGE_GUARD)
		return GUARD_EXCEPTION;



	if (*(BYTE*)dwFunctionAddress == 0xCC)
		return INT3_BREAKPOINT;
	if (*(BYTE*)dwFunctionAddress == 0x99)	/* (0xCC ^ 0x55) */
		return XORD_BREAKPOINT;

	if (*(BYTE*)dwFunctionAddress == 0x64)
		return PREFIX_1;
	if (*(BYTE*)dwFunctionAddress == 0x67)
		return PREFIX_2;

	if (*(BYTE*)dwFunctionAddress == 0x0F) {
		if (*(BYTE*)dwFunctionAddress + 1 == 0xB9)
			return UD1_BREAKPOINT;
		if (*(BYTE*)dwFunctionAddress + 1 == 0x10)
			return LONG_INT3_BREAKPOINT_1;
		if (*(BYTE*)dwFunctionAddress + 1 == 0x0B)
			return LONG_INT3_BREAKPOINT_2;
		if (*(BYTE*)dwFunctionAddress + 1 == 0x33)
			return RDPMC;
	}

	if (*(BYTE*)dwFunctionAddress == 0xCD) {
		if (*(BYTE*)dwFunctionAddress + 1 == 0xCE)
			return UD2_BREAKPOINT_1;
		if (*(BYTE*)dwFunctionAddress + 1 == 0x03)
			return UD2_BREAKPOINT_2;
		if (*(BYTE*)dwFunctionAddress + 1 == 0x01)
			return UD2_BREAKPOINT_3;
	}

	if (*(BYTE*)dwFunctionAddress == 0xF1)
		return ICE_BREAKPOINT;


	if (*(BYTE*)dwFunctionAddress == 0x2C)
		return INTERRUPT_1;
	if (*(BYTE*)dwFunctionAddress == 0x2D)
		return INTERRUPT_2;
	if (*(BYTE*)dwFunctionAddress == 0x41)
		return INTERRUPT_3;



	MODULEINFO mi;
	if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(0), &mi, sizeof(mi)))
		return FUNCTION_INFO_FAIL;

	auto dwLowAddress = reinterpret_cast<DWORD>(mi.lpBaseOfDll);
	auto dwHighAddress = dwLowAddress + mi.SizeOfImage;

	if (!IsLegitReturnAddressEBP(dwFunctionAddress, dwLowAddress, dwHighAddress))
		return UNKNOWN_EBP;



	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(NtCurrentThread, &ctx))
		if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr6 || ctx.Dr7)
			return HARDWARE_BP;



	PUCHAR pOpcode;
	DWORD dwFuncLength = SizeOfCode(pFunction, &pOpcode);

	if (piFunctionSize)
		*piFunctionSize = dwFuncLength;

	auto iBpCount = GetBreakpointCount(dwFunctionAddress, dwFuncLength);
	if (piBpCount)
		*piBpCount = iBpCount;

	if (pdwChecksum)
		*pdwChecksum = GetChecksum(pFunction, dwFuncLength);


	return DONE;
}


FunctionValidator::CFunctionValidator::CFunctionValidator()
{
	RtlComputeCrc32 = (lpRtlComputeCrc32)GetProcAddress(LoadLibraryA("ntdll"), "RtlComputeCrc32");
}

