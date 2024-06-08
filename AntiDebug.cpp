#include "AntiDebug.h"

#pragma comment(lib, "Kernel32.lib")

std::mutex AntiDebug::mutex;
std::unique_ptr<AntiDebug> AntiDebug::instance;

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
	);

AntiDebug* AntiDebug::getInstance() {
	if (!instance) {
		std::lock_guard<std::mutex> lock(mutex);
		if (!instance) {
			instance.reset(new AntiDebug());
		}
	}
	return instance.get();
}

bool AntiDebug::checkRemoteDebuggerPresent() const {
	BOOL isDebuggerPresent = FALSE;
	return CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent;
}

bool AntiDebug::checkDebuggerPresent() const {
	return IsDebuggerPresent() != FALSE;
}

bool AntiDebug::checkHardwareBreakpoints() const {
	CONTEXT context;
	memset(&context, 0, sizeof(CONTEXT));
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &context)) {
		// Handle error
		return false;
	}

	return (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3) &&
		((context.Dr7 & 0x1) || (context.Dr7 & 0x4) || (context.Dr7 & 0x10) || (context.Dr7 & 0x40));
}

bool AntiDebug::hardwareRegistersBreakpointsDetection() const {
	CONTEXT context;
	memset(&context, 0, sizeof(CONTEXT)); // Initialize the context structure
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	HANDLE currentThread = GetCurrentThread();

	// Retrieve the thread context
	if (GetThreadContext(currentThread, &context)) {
		if ((context.Dr0 != 0x00 || context.Dr1 != 0x00 || context.Dr2 != 0x00 || context.Dr3 != 0x00 ||
			context.Dr6 != 0x00 || context.Dr7 != 0x00)) {
			CloseHandle(currentThread);
			return true;
		}
	}
	CloseHandle(currentThread);
	return false;
}

bool AntiDebug::checkBeingDebuggedFlagPEB() const {
	PEB* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
	return peb->BeingDebugged != FALSE;
}

bool AntiDebug::heapProtectionCheck() const {
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == nullptr) {
		return false;
	}

	PROCESS_HEAP_ENTRY heapEntry;
	heapEntry.lpData = nullptr; // Initialize to null pointer

	while (HeapWalk(hHeap, &heapEntry)) {
		if ((heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) &&
			(heapEntry.lpData != nullptr)) {
			// Ensure lpData points to at least sizeof(DWORD) bytes
			if (heapEntry.cbData >= sizeof(DWORD)) {
				DWORD* pData = reinterpret_cast<DWORD*>(heapEntry.lpData);
				if (*pData == 0xABABABAB) {
					return true;
				}
			}
		}
	}

	return false;
}

bool AntiDebug::checkKUserSharedDataStructure() const {
	unsigned char* kuserDataAddress = reinterpret_cast<unsigned char*>(0x7ffe02d4);
	unsigned char b = *kuserDataAddress;
	return ((b & 0x01) || (b & 0x02));
}

bool AntiDebug::checkNtProcessDebugPort() const {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll) {
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
			hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess) {
			DWORD dwProcessDebugPort, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(
				GetCurrentProcess(),
				ProcessDebugPort,
				&dwProcessDebugPort,
				sizeof(DWORD),
				&dwReturned);

				FreeLibrary(hNtdll);
			if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort)) {
				return true;
			}
		}
		FreeLibrary(hNtdll);
	}
	return false;
}

bool AntiDebug::AntiDebugAttach() const {
	HMODULE NtdllModule = GetModuleHandle(TEXT("ntdll.dll"));
	if (!NtdllModule) {
		// Handle error
		return false;
	}

	FARPROC DbgUiRemoteBreakinAddress = GetProcAddress(NtdllModule, "DbgUiRemoteBreakin");
	FARPROC DbgBreakPointAddress = GetProcAddress(NtdllModule, "DbgBreakPoint");
	BYTE Int3InvaildCode[] = { 0xCC };
	BYTE RetCode[] = { 0xC3 };
	HANDLE hProcess = GetCurrentProcess();

	BOOL Status = WriteProcessMemory(hProcess, DbgUiRemoteBreakinAddress, Int3InvaildCode, sizeof(Int3InvaildCode), NULL);
	BOOL Status2 = WriteProcessMemory(hProcess, DbgBreakPointAddress, RetCode, sizeof(RetCode), NULL);

	if (Status && Status2)
		return true;
	return false;
}
