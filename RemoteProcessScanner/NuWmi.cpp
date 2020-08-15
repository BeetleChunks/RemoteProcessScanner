/*
	https://docs.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-variant
	https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-oaut/3fe7db9f-5803-4dc4-9d14-5425d3f5461f
*/

// For debugging use -> __debugbreak();

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <comdef.h>
#include <wincred.h>
#include <strsafe.h>
#include "NuWmi.h"
#include <map>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")

/*
	CONSTRUCTORS
*/
NuWmi::NuWmi(std::wstring domain, std::wstring username, std::wstring password, std::wstring server) {
	setDomain(domain);
	setUsername(username);
	setPassword(password);
	setServer(server);
	setResource(server);
	setAuthority(domain);
}

/*
	PRIVATE METHODS
*/
BOOL NuWmi::NuInitComLibrary() {
	HRESULT hres;

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);

	if (FAILED(hres)) {
		NuPrintWmiError(hres);
		return FALSE;
	}

	return TRUE;
}

BOOL NuWmi::NuSetComSecurity() {
	HRESULT hres;

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);

	if (FAILED(hres)) {
		NuPrintWmiError(hres);
		CoUninitialize();
		return FALSE;
	}

	return TRUE;
}

BOOL NuWmi::NuObtainWmiLocator() {
	HRESULT hres;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID*)&m_wmiconn.pLoc
	);

	if (FAILED(hres))
	{
		NuPrintWmiError(hres);
		CoUninitialize();
		return FALSE;
	}

	return TRUE;
}

BOOL NuWmi::NuWmiConnect() {
	HRESULT hres;

	hres = m_wmiconn.pLoc->ConnectServer(
		m_wmiconn.bsResource,
		m_wmiconn.bsUsername,
		m_wmiconn.bsPassword,
		NULL,
		NULL,
		m_wmiconn.bsAuthority,
		NULL,
		&m_wmiconn.pSvc
	);

	if (FAILED(hres)) {
		NuPrintWmiError(hres);
		m_wmiconn.pLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	return TRUE;
}

BOOL NuWmi::NuCreateAuthIdent() {
	memset(&m_wmiconn.authIdent, 0, sizeof(COAUTHIDENTITY));
	m_wmiconn.authIdent.PasswordLength = wcslen(m_wmiconn.bsPassword);
	m_wmiconn.authIdent.Password = (USHORT*)m_wmiconn.bsPassword;

	m_wmiconn.authIdent.User = (USHORT*)m_wmiconn.bsUsername;
	m_wmiconn.authIdent.UserLength = wcslen(m_wmiconn.bsUsername);

	m_wmiconn.authIdent.Domain = (USHORT*)m_wmiconn.bsDomain;
	m_wmiconn.authIdent.DomainLength = wcslen(m_wmiconn.bsDomain);

	m_wmiconn.authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

	m_wmiconn.userAcct = &m_wmiconn.authIdent;

	return TRUE;
}

BOOL NuWmi::NuSetWmiConnectionSecurity() {
	HRESULT hres;

	hres = CoSetProxyBlanket(
		m_wmiconn.pSvc,                 // Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		m_wmiconn.userAcct,             // client identity
		EOAC_NONE                       // proxy capabilities 
	);

	if (FAILED(hres)) {
		NuPrintWmiError(hres);
		m_wmiconn.pSvc->Release();
		m_wmiconn.pLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	return TRUE;
}

BOOL NuWmi::NuSecureEnumerator() {
	HRESULT hres;

	hres = CoSetProxyBlanket(
		m_wmiconn.pEnumerator,          // Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		m_wmiconn.userAcct,             // client identity
		EOAC_NONE                       // proxy capabilities 
	);

	if (FAILED(hres)) {
		NuPrintWmiError(hres);
		m_wmiconn.pEnumerator->Release();
		m_wmiconn.pSvc->Release();
		m_wmiconn.pLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	return TRUE;
}

BOOL NuWmi::NuClearCredsInMemory() {
	SecureZeroMemory(m_wmiconn.bsUsername, sizeof(m_wmiconn.bsUsername));
	SecureZeroMemory(m_wmiconn.bsPassword, sizeof(m_wmiconn.bsPassword));
	SecureZeroMemory(m_wmiconn.bsDomain, sizeof(m_wmiconn.bsDomain));

	return TRUE;
}

BOOL NuWmi::NuWmiDisconnect() {
	if (m_wmiconn.pSvc)
		m_wmiconn.pSvc->Release();

	if (m_wmiconn.pLoc)
		m_wmiconn.pLoc->Release();

	if (m_wmiconn.pEnumerator)
		m_wmiconn.pEnumerator->Release();

	if (m_wmiconn.pclsObj)
		m_wmiconn.pclsObj->Release();

	CoUninitialize();

	return TRUE;
}

// Print helper functions
VOID NuWmi::NuPrintWmiError(HRESULT hres) {
	LPTSTR errorText = NULL;   // Buffer for text
	DWORD dwChars;   // Number of chars returned
	HINSTANCE hInst;

	// Try to get message from the system errors
	dwChars = FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		hres,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&errorText,
		0,
		NULL);

	if (dwChars == 0) {
		/*
			The error code did not exist in the system
			errors. Trying wmiutils.dll for the error code.
		*/

		// Load the library
		hInst = LoadLibrary(L"C:\\Windows\\System32\\wbem\\wmiutils.dll");
		if (hInst == NULL) {
			std::wcout << L"Unable to load wmiutils.dll to display error code: " << std::hex << hres << std::endl;
			return;
		}

		// Try to get message from system
		dwChars = FormatMessage(
			FORMAT_MESSAGE_FROM_HMODULE |
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			hInst,
			hres,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&errorText,
			0,
			NULL);

		// Free library
		FreeLibrary(hInst);

		// Display the error message, or generic text if not found
		if (errorText != NULL) {
			std::wcout << L"WMI Error(" << std::hex << hres << L"): " << errorText;

			// release memory allocated by FormatMessage()
			LocalFree(errorText);
			errorText = NULL;
		}
		else {
			std::wcout << L"WMI Error(" << std::hex << hres << L")" << std::endl;
		}

		return;
	}

	// Display the error message, or generic text if not found
	if (errorText != NULL) {
		std::wcout << L"System Error(" << std::hex << hres << L"): " << errorText;

		// release memory allocated by FormatMessage()
		LocalFree(errorText);
		errorText = NULL;
	}
	else {
		std::wcout << L"System Error(" << std::hex << hres << L")" << std::endl;
	}
}

// Initialize WMIAUTH struct
VOID NuWmi::setDomain(std::wstring domain) {
	m_wmiauth.domain = domain;
	m_wmiconn.bsDomain = SysAllocStringLen(domain.data(), domain.size());
}

VOID NuWmi::setUsername(std::wstring username) {
	m_wmiauth.username = username;
	m_wmiconn.bsUsername = SysAllocStringLen(username.data(), username.size());
}

VOID NuWmi::setPassword(std::wstring password) {
	m_wmiauth.password = password;
	m_wmiconn.bsPassword = SysAllocStringLen(password.data(), password.size());
}

VOID NuWmi::setServer(std::wstring server) {
	m_wmiauth.server = server;
}

VOID NuWmi::setResource(std::wstring server) {
	m_wmiauth.resource = L"\\\\" + server + L"\\root\\cimv2";
	m_wmiconn.bsResource = SysAllocStringLen(m_wmiauth.resource.data(), m_wmiauth.resource.size());
}

VOID NuWmi::setAuthority(std::wstring domain) {
	m_wmiauth.authority = L"NTLMDOMAIN:" + domain;
	m_wmiconn.bsAuthority = SysAllocStringLen(m_wmiauth.authority.data(), m_wmiauth.authority.size());
}

// Enumeration Functions
BOOL NuWmi::NuEnumProcesses(std::vector <std::vector <NuWmi::WMIPARAM>>& vec2DVarResults) {
	HRESULT hres;
	ULONG uReturn = 0;
	SAFEARRAY* psaNames = NULL;

	long execQueryFlags = WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY;

	// Get instance of GetOwner() method
	IWbemClassObject* pClass = NULL;
	hres = m_wmiconn.pSvc->GetObject(_bstr_t(L"Win32_Process"), 0, NULL, &pClass, NULL);
	if (FAILED(hres)) {
		//NuPrintWmiError(hres);
		m_wmiconn.pSvc->Release();
		m_wmiconn.pLoc->Release();
		CoUninitialize();

		return FALSE;
	}

	IWbemClassObject* pMethodGetOwner = NULL;
	hres = pClass->GetMethod(_bstr_t(L"GetOwner"), 0, NULL, &pMethodGetOwner);
	if (FAILED(hres)) {
		//NuPrintWmiError(hres);
		m_wmiconn.pSvc->Release();
		m_wmiconn.pLoc->Release();
		CoUninitialize();

		return FALSE;
	}

	IWbemClassObject* pInstGetOwner = NULL;
	hres = pMethodGetOwner->SpawnInstance(0, &pInstGetOwner);
	if (FAILED(hres)) {
		//NuPrintWmiError(hres);
		m_wmiconn.pSvc->Release();
		m_wmiconn.pLoc->Release();
		CoUninitialize();

		return FALSE;
	}

	// Execute query to get enumerator of process intances
	hres = m_wmiconn.pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT * FROM Win32_Process"), execQueryFlags, NULL, &m_wmiconn.pEnumerator);
	if (FAILED(hres)) {
		//NuPrintWmiError(hres);
		m_wmiconn.pSvc->Release();
		m_wmiconn.pLoc->Release();
		CoUninitialize();

		return FALSE;
	}

	if (!NuSecureEnumerator())
		return FALSE;

	UINT j = 0;
	while (m_wmiconn.pEnumerator) {
		HRESULT hres = m_wmiconn.pEnumerator->Next(WBEM_INFINITE, 1, &m_wmiconn.pclsObj, &uReturn);
		if (uReturn == 0) {
			break;
		}

		std::vector <NuWmi::WMIPARAM> vecVarResults;
		vec2DVarResults.push_back(vecVarResults);

		hres = m_wmiconn.pclsObj->GetNames(NULL, WBEM_FLAG_ALWAYS, NULL, &psaNames);
		if (FAILED(hres)) {
			//NuPrintWmiError(hres);
			m_wmiconn.pclsObj->Release();
			m_wmiconn.pclsObj = NULL;

			return FALSE;
		}

		// Get the number of properties
		long lLower, lUpper;

		SafeArrayGetLBound(psaNames, 1, &lLower);
		SafeArrayGetUBound(psaNames, 1, &lUpper);

		for (long i = lLower; i <= lUpper; i++) {
			NuWmi::WMIPARAM wmiVarRes;

			// Get this property
			hres = SafeArrayGetElement(
				psaNames,
				&i,
				&wmiVarRes.bsParamName
			);

			// Get property value
			hres = m_wmiconn.pclsObj->Get(wmiVarRes.bsParamName, 0, &wmiVarRes.varParameter, 0, 0);

			vec2DVarResults[j].push_back(wmiVarRes);
		}

		// Execute Method GetOwner()
		VARIANT vtProp;
		hres = m_wmiconn.pclsObj->Get(_bstr_t(L"__PATH"), 0, &vtProp, 0, 0);
		if (FAILED(hres))
		{
			//NuPrintWmiError(hres);
			m_wmiconn.pclsObj->Release();
			continue;
		}

		hres = m_wmiconn.pSvc->ExecMethod(vtProp.bstrVal, _bstr_t(L"GetOwner"), 0, NULL, NULL, &pMethodGetOwner, NULL);
		if (FAILED(hres))
		{
			//std::wcout << L"ExecMethod() failed to get owner information for process " << j << std::endl;
			//NuPrintWmiError(hres);
		}
		else {
			NuWmi::WMIPARAM wmiVarOutDomain;
			wmiVarOutDomain.bsParamName = SysAllocString(L"Domain");
			hres = pMethodGetOwner->Get(wmiVarOutDomain.bsParamName, 0, &wmiVarOutDomain.varParameter, NULL, 0);
			if (FAILED(hres)) {
				//NuPrintWmiError(hres);
			}
			else if (wmiVarOutDomain.varParameter.vt != 0x1) {
				vec2DVarResults[j].push_back(wmiVarOutDomain);
			}

			NuWmi::WMIPARAM wmiVarOutUser;
			wmiVarOutUser.bsParamName = SysAllocString(L"User");
			hres = pMethodGetOwner->Get(wmiVarOutUser.bsParamName, 0, &wmiVarOutUser.varParameter, NULL, 0);
			if (FAILED(hres)) {
				//NuPrintWmiError(hres);
			}
			else if (wmiVarOutUser.varParameter.vt != 0x1) {
				vec2DVarResults[j].push_back(wmiVarOutUser);
			}
		}

		SafeArrayDestroy(psaNames);
		uReturn = 0;

		m_wmiconn.pclsObj->Release();
		m_wmiconn.pclsObj = NULL;

		j++;
	}

	return TRUE;
}

/*
	PUBLIC METHODS
*/

// Connection Functions
BOOL NuWmi::WmiConnect() {
	m_wmiconn.pLoc = NULL;
	m_wmiconn.pSvc = NULL;
	m_wmiconn.userAcct = NULL;
	m_wmiconn.pEnumerator = NULL;
	m_wmiconn.pclsObj = NULL;

	if (!NuInitComLibrary())
		return FALSE;

	if (!NuSetComSecurity())
		return FALSE;

	if (!NuObtainWmiLocator())
		return FALSE;

	if (!NuWmiConnect())
		return FALSE;

	if (!NuCreateAuthIdent())
		return FALSE;

	if (!NuSetWmiConnectionSecurity())
		return FALSE;

	return TRUE;
}

BOOL NuWmi::WmiDisconnect() {
	if (!NuClearCredsInMemory())
		return FALSE;

	if (!NuWmiDisconnect())
		return FALSE;

	return TRUE;
}

// Enumeration Functions
BOOL NuWmi::WmiEnumProcesses(std::vector <std::map<std::wstring, std::wstring>>& vMapResults) {
	std::vector <std::vector <NuWmi::WMIPARAM>> vec2DVarResults;

	// Enumerate processes
	if (!NuEnumProcesses(vec2DVarResults)) {
		std::wcout << L"Enumerating processes failed..." << std::endl;
		return FALSE;
	}

	// Iterate through vector of process vectors
	UINT i = 0;
	UINT j = 0;
	while (i < vec2DVarResults.size()) {
		std::map<std::wstring, std::wstring> mapResults;
		std::wstring key, value;

		// Iterate through current process vector of variants
		j = 0;
		while (j < vec2DVarResults[i].size()) {
			key = _bstr_t(vec2DVarResults[i][j].bsParamName, FALSE);

			if (key == L"__PATH") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"Caption") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"CommandLine") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"CreationDate") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"CSName") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"Description") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"Domain") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"ExecutablePath") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"Handle") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"HandleCount") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_I4)
					value = std::to_wstring(vec2DVarResults[i][j].varParameter.intVal);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"Name") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"OSName") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"ParentProcessId") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_I4)
					value = std::to_wstring(vec2DVarResults[i][j].varParameter.intVal);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"Priority") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_I4)
					value = std::to_wstring(vec2DVarResults[i][j].varParameter.intVal);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"ProcessId") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_I4)
					value = std::to_wstring(vec2DVarResults[i][j].varParameter.intVal);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"SessionId") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_I4)
					value = std::to_wstring(vec2DVarResults[i][j].varParameter.intVal);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"ThreadCount") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_I4)
					value = std::to_wstring(vec2DVarResults[i][j].varParameter.intVal);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"User") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"UserModeTime") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else if (key == L"WindowsVersion") {
				if (V_VT(&vec2DVarResults[i][j].varParameter) == VT_BSTR)
					value = _bstr_t(vec2DVarResults[i][j].varParameter.bstrVal, FALSE);
				else
					value = _bstr_t(L"");
			}
			else {
				j++;
				continue;
			}

			mapResults[key] = value;

			j++;
		}

		mapResults[L"Target"] = m_wmiauth.server;

		vMapResults.push_back(mapResults);

		i++;
	}

	return TRUE;
}