/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
**           2020-2023 SysCo systemes de communication sa
** Author: Nils Behlen
**         Yann Jeanrenaud, Andre Liechti
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#include "Configuration.h"
#include "Utilities.h"
#include "version.h"
#include "Logger.h"
#include "RegistryReader.h"
#include "MultiOTPRegistryReader.h"

using namespace std;

const wstring Configuration::registryPath = L"CLSID\\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}\\";
const wstring Configuration::registryRealmPath = L"CLSID\\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}\\realm-mapping";

Configuration::Configuration()
{
	MultiOTPRegistryReader rr(registryPath);

	// Credential Provider specific config
	bitmapPath = rr.getRegistry(L"v1_bitmap_path");
	hideDomainName = rr.getBoolRegistry(L"hide_domainname");
	hideFullName = rr.getBoolRegistry(L"hide_fullname");
	hide_otp_sleep_s = rr.getIntRegistry(L"hide_otp_sleep_s");

	twoStepHideOTP = rr.getBoolRegistry(L"two_step_hide_otp");
	twoStepSendEmptyPassword = rr.getBoolRegistry(L"two_step_send_empty_password");
	twoStepSendPassword = rr.getBoolRegistry(L"two_step_send_password");

	piconfig.logPasswords = rr.getBoolRegistry(L"log_sensitive");
	releaseLog = rr.getBoolRegistry(L"release_log");

	showDomainHint = rr.getBoolRegistry(L"show_domain_hint");
	// Custom field texts: check if set, otherwise use defaults (from header)
	wstring tmp = rr.getRegistry(L"login_text");
	loginText = tmp.empty() ? L"privacyIDEA Login" : tmp;

	otpFieldText = rr.getRegistry(L"otp_text");

	tmp = rr.getRegistry(L"otp_fail_text");
	defaultOTPFailureText = tmp.empty() ? Utilities::GetTranslatedText(TEXT_WRONG_OTP) : tmp;

	tmp = rr.getRegistry(L"otp_hint_text");
	defaultOTPHintText = tmp.empty() ? Utilities::GetTranslatedText(TEXT_DEFAULT_OTP_HINT) : tmp;

	// Config for PrivacyIDEA
	piconfig.hostname = rr.getRegistry(L"hostname");
	// Check if the path contains the placeholder, if so replace with nothing
	tmp = rr.getRegistry(L"path");
	piconfig.path = (tmp == L"/path/to/pi" ? L"" : tmp);

	piconfig.ignoreUnknownCA = rr.getBoolRegistry(L"ssl_ignore_unknown_ca");
	piconfig.ignoreInvalidCN = rr.getBoolRegistry(L"ssl_ignore_invalid_cn");
	piconfig.customPort = rr.getIntRegistry(L"custom_port");
	piconfig.offlineFilePath = rr.getRegistry(L"offline_file");
	piconfig.offlineTryWindow = rr.getIntRegistry(L"offline_try_window");

	piconfig.resolveTimeoutMS = rr.getIntRegistry(L"resolve_timeout");
	piconfig.connectTimeoutMS = rr.getIntRegistry(L"connect_timeout");
	piconfig.sendTimeoutMS = rr.getIntRegistry(L"send_timeout");
	piconfig.receiveTimeoutMS = rr.getIntRegistry(L"receive_timeout");

	// format domain\username or computername\username
	excludedAccount = rr.getRegistry(L"excluded_account");

	// e.g. "192.168.1.1;192.196.1.2"
	excludedAddresses = rr.getRegistry(L"excluded_address");

	// Realm Mapping
	piconfig.defaultRealm = rr.getRegistry(L"default_realm");

	if (!rr.getAll(registryRealmPath, piconfig.realmMap))
	{
		piconfig.realmMap.clear();
	}

	// Validate that only one of hideDomainName OR hideFullName is active
	// In the installer it is exclusive but could be changed in the registry
	if (hideDomainName && hideFullName)
	{
		hideDomainName = false;
	}
	// Validate 2Step
	if (twoStepSendEmptyPassword || twoStepSendPassword)
	{
		twoStepHideOTP = true;
	}
	if (twoStepSendEmptyPassword && twoStepSendPassword)
	{
		twoStepSendEmptyPassword = false;
	}

	// Get the Windows Version, deprecated 
	OSVERSIONINFOEX info;
	ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&info);

	winVerMajor = info.dwMajorVersion;
	winVerMinor = info.dwMinorVersion;
	winBuildNr = info.dwBuildNumber;
}

// for printing
inline wstring b2ws(bool b) {
	return b ? wstring(L"true") : wstring(L"false");
}

void Configuration::printConfiguration()
{
	DebugPrint("-----------------------------");
	DebugPrint("CP Version: " + string(VER_FILE_VERSION_STR));
	DebugPrint(L"Windows Version: " + to_wstring(winVerMajor) + L"." + to_wstring(winVerMinor)
		+ L"." + to_wstring(winBuildNr));
	DebugPrint("------- Configuration -------");
	DebugPrint(L"Hostname: " + piconfig.hostname);
	DebugPrint(L"Path: " + piconfig.path);
	DebugPrint(L"Custom port: " + to_wstring(piconfig.customPort));
	DebugPrint(L"Resolve timeout: " + to_wstring(piconfig.resolveTimeoutMS));
	DebugPrint(L"Connect timeout: " + to_wstring(piconfig.connectTimeoutMS));
	DebugPrint(L"Send timeout: " + to_wstring(piconfig.sendTimeoutMS));
	DebugPrint(L"Receive timeout: " + to_wstring(piconfig.receiveTimeoutMS));
	DebugPrint(L"Login text: " + loginText);
	DebugPrint(L"OTP field text: " + otpFieldText);
	DebugPrint(L"OTP failure text: " + defaultOTPFailureText);
	DebugPrint(L"Hide domain only: " + b2ws(hideDomainName));
	DebugPrint(L"Hide full name: " + b2ws(hideFullName));
	DebugPrint(L"SSL ignore invalid CN: " + b2ws(piconfig.ignoreUnknownCA));
	DebugPrint(L"SSL ignore invalid CN: " + b2ws(piconfig.ignoreInvalidCN));
	DebugPrint(L"2step hide OTP: " + b2ws(twoStepHideOTP));
	DebugPrint(L"2step send empty PW: " + b2ws(twoStepSendEmptyPassword));
	DebugPrint(L"2step send domain PW: " + b2ws(twoStepSendPassword));
	DebugPrint(L"Release Log: " + b2ws(releaseLog));
	DebugPrint(L"Log sensitive data: " + b2ws(piconfig.logPasswords));
	DebugPrint(L"No default: " + b2ws(noDefault));
	DebugPrint(L"Show domain hint: " + b2ws(showDomainHint));
	DebugPrint(L"Bitmap path: " + bitmapPath);
	DebugPrint(L"Offline file path: " + piconfig.offlineFilePath);
	DebugPrint(L"Offline try window: " + to_wstring(piconfig.offlineTryWindow));
	DebugPrint(L"Default realm: " + piconfig.defaultRealm);

	wstring tmp;
	for (const auto& item : piconfig.realmMap)
	{
		tmp += item.first + L"=" + item.second + L", ";
	}
	DebugPrint("Realm mapping:");
	DebugPrint(tmp.substr(0, tmp.size() - 2).c_str());

	DebugPrint("-----------------------------");
}