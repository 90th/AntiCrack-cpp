#ifndef ANTIDEBUG_H
#define ANTIDEBUG_H

#include <windows.h>
#include <mutex>
#include <memory>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>

class AntiDebug {
public:
	// Static method to get the single instance of the class
	static AntiDebug* getInstance();

	// Anti-debugging check methods
	bool checkRemoteDebuggerPresent() const;
	bool checkDebuggerPresent() const;
	bool checkHardwareBreakpoints() const;
	bool hardwareRegistersBreakpointsDetection() const;
	bool checkBeingDebuggedFlagPEB() const;
	bool heapProtectionCheck() const;
	bool checkKUserSharedDataStructure() const;
	bool checkNtProcessDebugPort() const;
private:

	// Singleton instance
	static std::unique_ptr<AntiDebug> instance;

	// Mutex for thread safety
	static std::mutex mutex;
};

#endif // ANTIDEBUG_H
