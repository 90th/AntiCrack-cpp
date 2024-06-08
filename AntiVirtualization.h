#ifndef ANTIVIRTUALIZATION_H
#define ANTIVIRTUALIZATION_H

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <fstream>
#include <string>
#include <filesystem>
#include <algorithm>
#include <Lmcons.h>
#include <thread>
#include <chrono>
#include <mutex>
#include <comdef.h>
#include <wbemidl.h>
#include <memory> // Include memory header for smart pointers

class AntiVirtualization {
public:
	// Static method to get the single instance of the class
	static AntiVirtualization* getInstance();

	// Anti-virtualization check methods
	bool isSandboxiePresent() const;
	bool isComodoSandboxPresent() const;
	bool isQihoo360SandboxPresent() const;
	bool isCuckooSandboxPresent() const;
	bool isEmulationPresent() const;
	bool isWinePresent() const;
	bool checkForHyperV() const;
	bool checkForBlacklistedNames() const;
	bool badVMFilesDetection() const;
	bool badVMProcessNames() const;
	bool checkDevices() const;
	bool checkForParallels() const;
	bool checkForQemu() const;
	bool triageCheck() const;

private:

	// Singleton instance as unique_ptr
	static std::unique_ptr<AntiVirtualization> instance;

	// Mutex for thread safety
	static std::mutex mutex;
};

#endif // ANTIVIRTUALIZATION_H
