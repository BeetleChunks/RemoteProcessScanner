#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include "NuWmi.h"

void PrintUsage();
void ReplaceAll(std::wstring& str, std::wstring& from, std::wstring& to);
BOOL ResultsToCSV(std::vector <std::map<std::wstring, std::wstring>>& vMapResults, std::wstring& csvFilePath);
VOID WmiEnumProcesses(std::vector <std::wstring> vwsArgs);

int wmain(int argc, wchar_t** argv) {
	std::vector <std::wstring> vwsArgs;

	// Basic argument check
	if (argc > 11) {
		PrintUsage();
		return 1;
	}

	int i = 1;
	while (i < argc) {
		vwsArgs.push_back(argv[i]);
		i++;
	}

	WmiEnumProcesses(vwsArgs);
}

void PrintUsage() {
	std::wcout << L"Usage: rps.exe [options] --csv <out file>" << std::endl;
	std::wcout << L"-h\tPrint this usage screen" << std::endl;
	std::wcout << L"-t\tSingle target IP or hostname" << std::endl;
	std::wcout << L"-tL\tFile of line delimited target IPs or hostnames" << std::endl;
	//std::wcout << L"-tLC\tFile of line delimited targets with associated credentials" << std::endl;
	std::wcout << L"-d\tAuthentication domain" << std::endl;
	std::wcout << L"-u\tAuthentication username" << std::endl;
	std::wcout << L"-p\tAuthentication password" << std::endl;
	std::wcout << L"--csv\tCSV file path to store results" << std::endl;
}

void ReplaceAll(std::wstring& str, std::wstring& from, std::wstring& to) {
	if (from.empty())
		return;

	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
}

BOOL ResultsToCSV(std::vector <std::map<std::wstring, std::wstring>>& vMapResults, std::wstring& csvFilePath) {
	std::vector <std::wstring> vColumns;
	UINT i = 0;
	UINT j = 0;

	// Open target csv file for writing
	std::wofstream csvFile;
	csvFile.open(csvFilePath);

	// Create column keys from all result keys
	i = 0;
	while (i < vMapResults.size()) {
		for (auto it = vMapResults[i].cbegin(); it != vMapResults[i].cend(); ++it) {
			vColumns.push_back((*it).first);
		}

		// Unique vector here. Idea is to keep memory down
		std::sort(vColumns.begin(), vColumns.end());
		vColumns.erase(std::unique(vColumns.begin(), vColumns.end()), vColumns.end());

		i++;
	}

	// Create/Write column row
	std::wstring columnLine;

	i = 0;
	while (i < vColumns.size() - 1) {
		std::wstring value = vColumns[i];

		// Wrap in double quotes if value contains a comma
		if (value.find(L',') != std::wstring::npos) {
			// RFC-4180, paragraph 7. "If double-quotes are used to enclose fields,
			// then a double-quote appearing inside a field must be escaped by
			// preceding it with another double quote."
			std::wstring from = L"\"";
			std::wstring to = L"\"\"";

			ReplaceAll(value, from, to);

			columnLine += L"\"";
			columnLine += value;
			columnLine += L"\"";
			columnLine += L",";
		}
		else {
			columnLine += value;
			columnLine += L",";
		}

		i++;
	}
	std::wstring value = vColumns[i];

	// Wrap in double quotes if value contains a comma
	if (value.find(L',') != std::wstring::npos) {
		// RFC-4180, paragraph 7. "If double-quotes are used to enclose fields,
		// then a double-quote appearing inside a field must be escaped by
		// preceding it with another double quote."
		std::wstring from = L"\"";
		std::wstring to = L"\"\"";

		ReplaceAll(value, from, to);

		columnLine += L"\"";
		columnLine += value;
		columnLine += L"\"";
	}
	else {
		columnLine += value;
	}

	//std::wcout << columnLine << std::endl;
	csvFile << columnLine << std::endl;

	// Create/Write rows
	i = 0;
	while (i < vMapResults.size()) {
		std::wstring rowLine;

		j = 0;
		while (j < vColumns.size() - 1) {
			try {
				std::wstring value = vMapResults[i].at(vColumns[j]);

				// Wrap in double quotes if value contains a comma
				if (value.find(L',') != std::wstring::npos) {
					// RFC-4180 - paragraph 7 - "If double-quotes are used to enclose fields,
					// then a double-quote appearing inside a field must be escaped by
					// preceding it with another double quote."
					std::wstring from = L"\"";
					std::wstring to = L"\"\"";

					ReplaceAll(value, from, to);

					rowLine += L"\"";
					rowLine += value;
					rowLine += L"\"";
					rowLine += L",";
				}
				else {
					rowLine += value;
					rowLine += L",";
				}
			}
			catch (const std::out_of_range) {
				rowLine += L",";
			}

			j++;
		}
		try {
			std::wstring value = vMapResults[i].at(vColumns[j]);
			if (value.find(',') != std::wstring::npos) {
				// RFC-4180, paragraph "If double-quotes are used to enclose fields,
				// then a double-quote appearing inside a field must be escaped by
				// preceding it with another double quote."
				std::wstring from = L"\"";
				std::wstring to = L"\"\"";

				ReplaceAll(value, from, to);

				rowLine += L"\"";
				rowLine += value;
				rowLine += L"\"";
			}
			else {
				rowLine += value;
			}
		}
		catch (const std::out_of_range) {}

		//std::wcout << rowLine << std::endl;
		csvFile << rowLine << std::endl;
		rowLine.clear();

		i++;
	}

	csvFile.close();

	return TRUE;
}

VOID WmiEnumProcesses(std::vector <std::wstring> vwsArgs) {
	//__debugbreak();
	std::vector<std::map<std::wstring, std::wstring>> vMapTargets;
	std::vector<std::map<std::wstring, std::wstring>> vMapResults;

	BOOL bResult;
	BOOL bOutCsv = FALSE;

	std::wstring target;
	std::wstring targetsFile;
	std::wstring targetsCredsFile;
	std::wstring domain;
	std::wstring username;
	std::wstring password;
	std::wstring csvFilePath;

	if (vwsArgs.size() == 0) {
		PrintUsage();
		return;
	}

	size_t i = 0;
	while (i < vwsArgs.size()) {
		if (vwsArgs[i] == L"-t") {
			target = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-tL") {
			targetsFile = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-tLC") {
			targetsCredsFile = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-d") {
			domain = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-u") {
			username = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"-p") {
			password = vwsArgs[i + 1];
			i += 2;
		}
		else if (vwsArgs[i] == L"--csv") {
			csvFilePath = vwsArgs[i + 1];
			bOutCsv = TRUE;
			i += 2;
		}
		else if (vwsArgs[i] == L"-h") {
			PrintUsage();
			return;
		}
	}

	// CSV output file is required
	if (bOutCsv == FALSE) {
		std::wcout << L"Error: You must specify a CSV output file via '--csv'\n" << std::endl;

		PrintUsage();
		return;
	}

	// Single target via -t flag
	if (target.empty() == FALSE) {
		std::map<std::wstring, std::wstring> mapTargets;
		mapTargets[L"domain"] = domain;
		mapTargets[L"username"] = username;
		mapTargets[L"password"] = password;
		mapTargets[L"target"] = target;

		vMapTargets.push_back(mapTargets);
	}
	else if (targetsFile.empty() == FALSE) {
		std::wfstream fsTargets;
		fsTargets.open(targetsFile, std::ios::in);

		if (fsTargets.is_open()) {
			while (std::getline(fsTargets, target)) {
				std::map<std::wstring, std::wstring> mapTargets;
				mapTargets[L"domain"] = domain;
				mapTargets[L"username"] = username;
				mapTargets[L"password"] = password;
				mapTargets[L"target"] = target;

				vMapTargets.push_back(mapTargets);
			}
		}

		fsTargets.close();
	}
	else if (targetsCredsFile.empty() == FALSE) {
		// Need to complete this
		// Add to usage after complete
	}
	else {
		PrintUsage();
		return;
	}

	i = 0;
	while (i < vMapTargets.size()) {
		NuWmi nuwmi{
			vMapTargets[i][L"domain"],
			vMapTargets[i][L"username"],
			vMapTargets[i][L"password"],
			vMapTargets[i][L"target"] };

		std::wcout << L"[" << i+1 << L":" << vMapTargets.size() << L"] " << vMapTargets[i][L"target"] << L"...";

		bResult = nuwmi.WmiConnect();
		if (bResult == FALSE) {
			i++;
			continue;
		}

		std::wcout << L"Connected...";

		bResult = nuwmi.WmiEnumProcesses(vMapResults);
		if (bResult == FALSE) {
			std::wcout << L"Enumeration Failed" << std::endl;
			i++;
			continue;
		}

		std::wcout << L"Enumerated" << std::endl;

		bResult = nuwmi.WmiDisconnect();
		if (bResult == FALSE) {
			i++;
			continue;
		}

		i++;
	}

	// Save results to a CSV file
	bResult = ResultsToCSV(vMapResults, csvFilePath);
		
	if (bResult == FALSE)
		std::wcout << L"[!] ResultsToCSV() Failed" << std::endl;
}