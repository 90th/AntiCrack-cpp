# AntiCrack-cpp
![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/90th/AntiCrack-cpp/latest/total) ![GitHub last commit](https://img.shields.io/github/last-commit/90th/AntiCrack-cpp) ![GitHub Repo stars](https://img.shields.io/github/stars/90th/AntiCrack-cpp)

AntiCrack-cpp is a C++ library designed to provide anti-virtualization and anti-debugging capabilities for your applications. While it may not prevent determined attackers from reverse engineering or cracking your software entirely, it offers a set of foolproof examples to enhance the security of your code.

**it's important to note that no security solution can completely prevent determined attackers**.

## Features

- **Anti-Debugging Checks:** Prevent debugging attempts by detecting various debuggers and debugging techniques.
- **Virtualization Checks:** Identify common virtualization environments to thwart sandboxing and emulation.

### Anti-Debugging Checks:
- **checkRemoteDebuggerPresent():** Detects a remote debugger.
- **checkDebuggerPresent():** Detects attached debuggers.
- **checkHardwareBreakpoints():** Detects hardware breakpoints.
- **hardwareRegistersBreakpointsDetection():** Detects debug registers breakpoints.
- **checkBeingDebuggedFlagPEB():** Checks the PEB for debug flags.
- **heapProtectionCheck():** Detects heap protection.
- **checkKUserSharedDataStructure():** Detects debug info in KUSER_SHARED_DATA.
- **checkNtProcessDebugPort():** Detects debugging via PEB DebugPort.
- **AntiDebugAttach():** Modifies memory to hinder debugging

### Virtualization Checks:
- **isSandboxiePresent():** Detects Sandboxie.
- **isComodoSandboxPresent():** Detects Comodo Sandbox.
- **isQihoo360SandboxPresent():** Detects Qihoo 360 Sandbox.
- **isCuckooSandboxPresent():** Detects Cuckoo Sandbox.
- **isEmulationPresent():** Detects emulated environments.
- **isWinePresent():** Detects Wine.
- **checkForHyperV():** Detects Hyper-V virtualization.
- **badVMProcessNames():** Detects VM process names.
- **checkDevices():** Detects virtual devices.
- **checkForBlacklistedNames():** Detects blacklisted VM environment names.
- **badVMFilesDetection():** Detects VM-related files.
- **checkForParallels():** Detects Parallels virtualization.
- **checkForQemu():** Detects QEMU virtualization.
- **triageCheck():** Comprehensive virtualization and emulation check.


## Installation

- Anti-Debugging Checks: Provides functions to detect various debugging methods commonly used to analyze and manipulate code execution.
- Anti-Virtualization Checks: Offers functionality to identify common virtualization environments and sandboxes.

## Example

```cpp
#include <iostream>
#include <chrono>
#include <thread>
#include "AntiDebug.h"
#include "AntiVirtualization.h" 

int main() {
	AntiDebug* antiDebug = AntiDebug::getInstance();
	AntiVirtualization* antiVirtualization = AntiVirtualization::getInstance(); 

	while (true) {
		std::cout << "Anti-Debugging Checks:\n";
		std::cout << "checkRemoteDebuggerPresent(): " << (antiDebug->checkRemoteDebuggerPresent() ? "true" : "false") << "\n";
		std::cout << "checkDebuggerPresent(): " << (antiDebug->checkDebuggerPresent() ? "true" : "false") << "\n";
		std::cout << "checkHardwareBreakpoints(): " << (antiDebug->checkHardwareBreakpoints() ? "true" : "false") << "\n";
		std::cout << "hardwareRegistersBreakpointsDetection(): " << (antiDebug->hardwareRegistersBreakpointsDetection() ? "true" : "false") << "\n";
		std::cout << "checkBeingDebuggedFlagPEB(): " << (antiDebug->checkBeingDebuggedFlagPEB() ? "true" : "false") << "\n";
		std::cout << "heapProtectionCheck(): " << (antiDebug->heapProtectionCheck() ? "true" : "false") << "\n";
		std::cout << "checkKUserSharedDataStructure(): " << (antiDebug->checkKUserSharedDataStructure() ? "true" : "false") << "\n";
		std::cout << "checkNtProcessDebugPort(): " << (antiDebug->checkNtProcessDebugPort() ? "true" : "false") << "\n";
		std::cout << "AntiDebugAttach(): " << (antiDebug->AntiDebugAttach() ? "true" : "false") << "\n";


		std::cout << "\nVirtualization Checks:\n";
		std::cout << "isSandboxiePresent(): " << (antiVirtualization->isSandboxiePresent() ? "true" : "false") << "\n";
		std::cout << "isComodoSandboxPresent(): " << (antiVirtualization->isComodoSandboxPresent() ? "true" : "false") << "\n";
		std::cout << "isQihoo360SandboxPresent(): " << (antiVirtualization->isQihoo360SandboxPresent() ? "true" : "false") << "\n";
		std::cout << "isCuckooSandboxPresent(): " << (antiVirtualization->isCuckooSandboxPresent() ? "true" : "false") << "\n";
		std::cout << "isEmulationPresent(): " << (antiVirtualization->isEmulationPresent() ? "true" : "false") << "\n";
		std::cout << "isWinePresent(): " << (antiVirtualization->isWinePresent() ? "true" : "false") << "\n";
		std::cout << "checkForHyperV(): " << (antiVirtualization->checkForHyperV() ? "true" : "false") << "\n";
		std::cout << "badVMProcessNames(): " << (antiVirtualization->badVMProcessNames() ? "true" : "false") << "\n";
		std::cout << "checkDevices(): " << (antiVirtualization->checkDevices() ? "true" : "false") << "\n";
		std::cout << "checkForBlacklistedNames(): " << (antiVirtualization->checkForBlacklistedNames() ? "true" : "false") << "\n";
		std::cout << "badVMFilesDetection(): " << (antiVirtualization->badVMFilesDetection() ? "true" : "false") << "\n";
		std::cout << "checkForParallels(): " << (antiVirtualization->checkForParallels() ? "true" : "false") << "\n";
		std::cout << "checkForQemu(): " << (antiVirtualization->checkForQemu() ? "true" : "false") << "\n";
		std::cout << "triageCheck(): " << (antiVirtualization->triageCheck() ? "true" : "false") << "\n";

		// Sleep for 1 second before checking again
		std::this_thread::sleep_for(std::chrono::seconds(1));
		system("cls");
	}

	return 0;
}
```
## Contributing

Contributions are welcome! If you have any ideas for improvements or new features, feel free to open an issue or submit a pull request.

