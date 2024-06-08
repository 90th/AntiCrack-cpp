#include "AntiVirtualization.h"

#pragma comment(lib, "wbemuuid.lib")

std::mutex AntiVirtualization::mutex;
std::unique_ptr<AntiVirtualization> AntiVirtualization::instance;

AntiVirtualization* AntiVirtualization::getInstance() {
	if (!instance) {
		std::lock_guard<std::mutex> lock(mutex);
		if (!instance) {
			instance.reset(new AntiVirtualization());
		}
	}
	return instance.get();
}

bool AntiVirtualization::isSandboxiePresent() const {
	return (GetModuleHandle("SbieDll.dll") != nullptr);
}

bool AntiVirtualization::isComodoSandboxPresent() const {
	return (GetModuleHandle("cmdvrt32.dll") != nullptr || GetModuleHandle("cmdvrt64.dll") != nullptr);
}

bool AntiVirtualization::isQihoo360SandboxPresent() const {
	return (GetModuleHandle("SxIn.dll") != nullptr);
}

bool AntiVirtualization::isCuckooSandboxPresent() const {
	return (GetModuleHandle("cuckoomon.dll") != nullptr);
}

bool AntiVirtualization::isEmulationPresent() const {
	ULONGLONG tick = GetTickCount64();
	std::this_thread::sleep_for(std::chrono::milliseconds(500));
	ULONGLONG tick2 = GetTickCount64();
	return ((tick2 - tick) < 500);
}

bool AntiVirtualization::isWinePresent() const {
	HMODULE moduleHandle = GetModuleHandle("kernel32.dll");
	if (moduleHandle != nullptr) {
		FARPROC procAddress = GetProcAddress(moduleHandle, "wine_get_unix_file_name");
		return (procAddress != nullptr);
	}
	return false;
}

bool AntiVirtualization::checkForHyperV() const {
	std::vector<std::string> servicesToCheck = { "vmbus", "VMBusHID", "hyperkbd" };

	// Enumerate all services on the system
	SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (hSCManager == nullptr) {
		return false;
	}

	DWORD bytesNeeded, servicesCount;
	if (!EnumServicesStatus(hSCManager, SERVICE_WIN32, SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &servicesCount, nullptr)) {
		CloseServiceHandle(hSCManager);
		return false;
	}

	std::vector<BYTE> buffer(bytesNeeded);
	ENUM_SERVICE_STATUS* services = reinterpret_cast<ENUM_SERVICE_STATUS*>(buffer.data());

	if (!EnumServicesStatus(hSCManager, SERVICE_WIN32, SERVICE_ACTIVE, services, bytesNeeded, &bytesNeeded, &servicesCount, nullptr)) {
		CloseServiceHandle(hSCManager);
		return false;
	}

	CloseServiceHandle(hSCManager);

	// Check each service name
	for (DWORD i = 0; i < servicesCount; ++i) {
		std::string serviceName(services[i].lpServiceName);
		std::transform(serviceName.begin(), serviceName.end(), serviceName.begin(), ::tolower);

		for (const auto& serviceToCheck : servicesToCheck) {
			if (serviceName.find(serviceToCheck) != std::string::npos) {
				return true;
			}
		}
	}

	return false;
}

bool AntiVirtualization::badVMProcessNames() const {
	std::vector<std::string> badProcessNames = { "vboxservice", "VGAuthService", "vmusrvc", "qemu-ga" };

	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32 = { 0 }; // Explicitly initialize PROCESSENTRY32

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return false;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return false;
	}

	do {
		std::string processName = pe32.szExeFile;
		for (const auto& badProcessName : badProcessNames) {
			if (processName == badProcessName) {
				CloseHandle(hProcessSnap);
				return true;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return false;
}

bool AntiVirtualization::checkDevices() const {
	std::string devices[] = { "\\\\.\\pipe\\cuckoo", "\\\\.\\HGFS", "\\\\.\\vmci", "\\\\.\\VBoxMiniRdrDN", "\\\\.\\VBoxGuest", "\\\\.\\pipe\\VBoxMiniRdDN", "\\\\.\\VBoxTrayIPC", "\\\\.\\pipe\\VBoxTrayIPC" };

	for (const auto& device : devices) {
		HANDLE pipe = CreateFileA(device.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (pipe != INVALID_HANDLE_VALUE) {
			CloseHandle(pipe);
			return true;
		}
	}

	return false;
}

bool AntiVirtualization::checkForBlacklistedNames() const {
	std::vector<std::string> badNames = { "Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount" };

	char username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	if (!GetUserName(username, &username_len)) {
		return false;
	}

	std::string usernameStr(username);
	std::transform(usernameStr.begin(), usernameStr.end(), usernameStr.begin(), ::tolower);

	for (const auto& badUsername : badNames) {
		std::string lowerBadUsername = badUsername;
		std::transform(lowerBadUsername.begin(), lowerBadUsername.end(), lowerBadUsername.begin(), ::tolower);

		if (usernameStr == lowerBadUsername) {
			return true;
		}
	}

	return false;
}

bool AntiVirtualization::badVMFilesDetection() const {
	try {
		std::vector<std::string> badFileNames = { "VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vmmouse.sys", "vboxogl.dll" };
		std::vector<std::string> badDirs = { "C:\\Program Files\\VMware", "C:\\Program Files\\oracle\\virtualbox guest additions" };

		char systemPath[MAX_PATH];
		if (!GetSystemDirectory(systemPath, MAX_PATH)) {
			return false;
		}

		std::string systemDir(systemPath);

		for (const auto& entry : std::filesystem::directory_iterator(systemDir)) {
			if (entry.is_regular_file()) {
				std::string fileName = entry.path().filename().string();
				std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);

				for (const auto& badFileName : badFileNames) {
					std::string lowerBadFileName = badFileName;
					std::transform(lowerBadFileName.begin(), lowerBadFileName.end(), lowerBadFileName.begin(), ::tolower);

					if (fileName == lowerBadFileName) {
						return true;
					}
				}
			}
		}

		for (const auto& badDir : badDirs) {
			std::string lowerBadDir = badDir;
			std::transform(lowerBadDir.begin(), lowerBadDir.end(), lowerBadDir.begin(), ::tolower);

			if (std::filesystem::exists(lowerBadDir)) {
				return true;
			}
		}
	}
	catch (...) {
		// handle any exceptions if needed
	}

	return false;
}

bool AntiVirtualization::checkForParallels() const {
	std::vector<std::string> badDriversList = { "prl_sf", "prl_tg", "prl_eth" };
	for (const auto& driver : std::filesystem::directory_iterator("C:\\Windows\\System32")) {
		std::string driverName = driver.path().filename().string();
		for (const auto& badDriver : badDriversList) {
			if (driverName.find(badDriver) != std::string::npos) {
				return true;
			}
		}
	}
	return false;
}

bool AntiVirtualization::checkForQemu() const {
	const std::string badDrivers[] = { "qemu-ga", "qemuwmi" };

	char* systemRoot;
	size_t len;
	errno_t err = _dupenv_s(&systemRoot, &len, "SystemRoot");
	if (err != 0 || systemRoot == nullptr) {
		// Handle error if _dupenv_s fails
		return false;
	}

	std::filesystem::path systemRootPath(systemRoot);
	free(systemRoot); // Free the memory allocated by _dupenv_s

	for (const auto& driver : std::filesystem::directory_iterator(systemRootPath / "System32")) {
		for (const auto& badDriver : badDrivers) {
			if (driver.path().string().find(badDriver) != std::string::npos) {
				return true;
			}
		}
	}

	return false;
}

bool AntiVirtualization::triageCheck() const {
	HRESULT hres;

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		CoUninitialize();
		return false;              // Program has failed.
	}

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities
		NULL                         // Reserved
	);

	if (FAILED(hres)) {
		CoUninitialize();
		return false;              // Program has failed.
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	IWbemLocator* pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hres)) {
		CoUninitialize();
		return false;               // Program has failed.
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices* pSvc = NULL;

	// Connect to the root\cimv2 namespace with the current user and obtain pointer pSvc to make IWbemServices calls.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),  // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (e.g. Kerberos)
		0,                       // Context object
		&pSvc                    // pointer to IWbemServices proxy
	);

	if (FAILED(hres)) {
		pLoc->Release();
		CoUninitialize();
		return false;                // Program has failed.
	}

	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------
	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities
	);

	if (FAILED(hres)) {
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;               // Program has failed.
	}

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	// For example, query for operating system data
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_DiskDrive"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres)) {
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;               // Program has failed.
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject* pclsObj;
	ULONG uReturn = 0;

	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn) {
			break;
		}

		VARIANT vtProp;
		VariantInit(&vtProp); // Initialize VARIANT

		// Get the value of the Name property
		hr = pclsObj->Get(L"Model", 0, &vtProp, 0, 0);
		if (FAILED(hr)) {
			VariantClear(&vtProp);
			pclsObj->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return false;
		}

		std::wstring modelName = vtProp.bstrVal;
		VariantClear(&vtProp);

		if (modelName.find(L"DADY HARDDISK") != std::wstring::npos || modelName.find(L"QEMU HARDDISK") != std::wstring::npos) {
			pclsObj->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return true;
		}

		pclsObj->Release();
	}

	// Cleanup
	// =========

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return false;   // Program successfully completed.
}