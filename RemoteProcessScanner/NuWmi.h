#ifndef NUWMI_H
#define NUWMI_H
#include <Windows.h>
#include <iostream>
#include <Wbemidl.h>
#include <map>

class NuWmi {
	struct WMIPARAM {
		BSTR bsParamName;
		VARIANT varParameter;
	};

	struct WMIAUTH {
		std::wstring domain;
		std::wstring username;
		std::wstring password;
		std::wstring server;
		std::wstring resource;
		std::wstring authority;
	};

	struct WMICONN {
		IWbemLocator* pLoc;
		IWbemServices* pSvc;
		COAUTHIDENTITY* userAcct;
		COAUTHIDENTITY authIdent;
		IEnumWbemClassObject* pEnumerator;
		IWbemClassObject* pclsObj;
		BSTR bsDomain;
		BSTR bsUsername;
		BSTR bsPassword;
		BSTR bsResource;
		BSTR bsAuthority;
	};

	WMIAUTH m_wmiauth{};
	WMICONN m_wmiconn{};

private:
	BOOL NuInitComLibrary();
	BOOL NuSetComSecurity();
	BOOL NuObtainWmiLocator();
	BOOL NuWmiConnect();
	BOOL NuCreateAuthIdent();
	BOOL NuSetWmiConnectionSecurity();
	BOOL NuSecureEnumerator();
	BOOL NuClearCredsInMemory();
	BOOL NuWmiDisconnect();

	// Print helper functions
	VOID NuPrintWmiError(HRESULT hres);

	// Initialize WMIAUTH struct
	VOID setDomain(std::wstring domain);
	VOID setUsername(std::wstring username);
	VOID setPassword(std::wstring password);
	VOID setServer(std::wstring server);
	VOID setResource(std::wstring server);
	VOID setAuthority(std::wstring domain);

	// Enumeration Functions
	BOOL NuEnumProcesses(std::vector <std::vector <WMIPARAM>>& vec2DVarResults);

public:
	NuWmi(std::wstring domain, std::wstring username, std::wstring password, std::wstring server);

	// Connection Functions
	BOOL WmiConnect();
	BOOL WmiDisconnect();

	// Enumeration Functions
	BOOL WmiEnumProcesses(std::vector <std::map<std::wstring, std::wstring>>& vMapResults);
};

#endif