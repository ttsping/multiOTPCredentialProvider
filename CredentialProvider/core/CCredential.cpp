/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2012 Dominik Pretzsch
**				2017 NetKnights GmbH
**				2020-2021 SysCo systemes de communication sa
**
** Author		Dominik Pretzsch
**				Nils Behlen
**				Yann Jeanrenaud, Andre Liechti
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
** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include "CCredential.h"
#include "Configuration.h"
#include "Logger.h"
#include "json.hpp"
#include <resource.h>
#include <string>
#include <thread>
#include <future>
#include <sstream>
#include "MultiotpHelpers.h" // multiOTP/yj
#include "MultiotpRegistry.h" // multiOTP/yj
#include "Shared.h"

using namespace std;

CCredential::CCredential(std::shared_ptr<Configuration> c) :
	_config(c), _util(_config), _privacyIDEA(c->piconfig)
{
	_cRef = 1;
	_pCredProvCredentialEvents = nullptr;

	DllAddRef();

	_dwComboIndex = 0;

	ZERO(_rgCredProvFieldDescriptors);
	ZERO(_rgFieldStatePairs);
	ZERO(_rgFieldStrings);
}

CCredential::~CCredential()
{
	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, NULL, CLEAR_FIELDS_ALL_DESTROY);
	DllRelease();
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
// Optionally takes a password for the SetSerialization case.
HRESULT CCredential::Initialize(
	__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
	__in const FIELD_STATE_PAIR* rgfsp,
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name,
	__in_opt PWSTR password
)
{
	wstring wstrUsername, wstrDomainname;
	SecureWString wstrPassword;

	if (NOT_EMPTY(user_name))
	{
		wstrUsername = wstring(user_name);
	}
	if (NOT_EMPTY(domain_name))
	{
		wstrDomainname = wstring(domain_name);
	}
	if (NOT_EMPTY(password))
	{
		wstrPassword = SecureWString(password);
	}
#ifdef _DEBUG
	DebugPrint(__FUNCTION__);
	DebugPrint(L"Username from provider: " + (wstrUsername.empty() ? L"empty" : wstrUsername));
	DebugPrint(L"Domain from provider: " + (wstrDomainname.empty() ? L"empty" : wstrDomainname));
	if (_config->piconfig.logPasswords)
	{
		DebugPrint(L"Password from provider: " + (wstrPassword.empty() ? L"empty" : wstrPassword));
	}
#endif
	HRESULT hr = S_OK;

	if (!wstrUsername.empty())
	{
		DebugPrint("Copying user to credential");
		_config->credential.username = wstrUsername;
	}

	if (!wstrDomainname.empty())
	{
		DebugPrint("Copying domain to credential");
		_config->credential.domain = wstrDomainname;
	}

	if (!wstrPassword.empty())
	{
		DebugPrint("Copying password to credential");
		_config->credential.password = wstrPassword;
		SecureZeroMemory(password, sizeof(password));
	}

	for (DWORD i = 0; SUCCEEDED(hr) && i < FID_NUM_FIELDS; i++)
	{
		//DebugPrintLn("Copy field #:");
		//DebugPrintLn(i + 1);
		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);

		if (FAILED(hr))
		{
			break;
		}

		_util.InitializeField(_rgFieldStrings, i);
	}

	DebugPrint("Init result:");
	if (SUCCEEDED(hr))
	{
		DebugPrint("OK");
	}
	else
	{
		DebugPrint("FAIL");
	}

	return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CCredential::Advise(
	__in ICredentialProviderCredentialEvents* pcpce
)
{
	//DebugPrintLn(__FUNCTION__);

	if (_pCredProvCredentialEvents != nullptr)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = pcpce;
	_pCredProvCredentialEvents->AddRef();

	return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CCredential::UnAdvise()
{
	//DebugPrintLn(__FUNCTION__);

	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = nullptr;
	return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CCredential::SetSelected(__out BOOL* pbAutoLogon)
{
	DebugPrint(__FUNCTION__);
	*pbAutoLogon = false;
	HRESULT hr = S_OK;

	if (_config->doAutoLogon)
	{
		*pbAutoLogon = TRUE;
		_config->doAutoLogon = false;
	}

	if (_config->credential.passwordMustChange
		&& _config->provider.cpu == CPUS_UNLOCK_WORKSTATION
		&& _config->winVerMajor != 10)
	{
		// We cant handle a password change while the maschine is locked, so we guide the user to sign out and in again like windows does
		DebugPrint("Password must change in CPUS_UNLOCK_WORKSTATION");
		_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, L"Go back until you are asked to sign in.");
		_pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"To change your password sign out and in again.");
		_pCredProvCredentialEvents->SetFieldState(this, FID_LDAP_PASS, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);
	}

	if (_config->credential.passwordMustChange)
	{
		_util.SetScenario(this, _pCredProvCredentialEvents, SCENARIO::CHANGE_PASSWORD);
		if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
		{
			_config->bypassPrivacyIDEA = true;
		}
	}

	if (_config->credential.passwordChanged)
	{
		*pbAutoLogon = TRUE;
	}

	return hr;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CCredential::SetDeselected()
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);

	_util.ResetScenario(this, _pCredProvCredentialEvents);

	// Reset password changing in case another user wants to log in
	_config->credential.passwordChanged = false;
	_config->credential.passwordMustChange = false;

	return hr;
}

// Gets info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT CCredential::GetFieldState(
	__in DWORD dwFieldID,
	__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
	__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	// Validate paramters.
	if (dwFieldID < FID_NUM_FIELDS && pcpfs && pcpfis)
	{
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		*pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CCredential::GetStringValue(
	__in DWORD dwFieldID,
	__deref_out PWSTR* ppwsz
)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	// Check to make sure dwFieldID is a legitimate index.
	if (dwFieldID < FID_NUM_FIELDS && ppwsz)
	{
		// Make a copy of the string and return that. The caller
		// is responsible for freeing it.
		hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

// Gets the image to show in the user tile.
HRESULT CCredential::GetBitmapValue(
	__in DWORD dwFieldID,
	__out HBITMAP* phbmp
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = E_INVALIDARG;
	if ((FID_LOGO == dwFieldID) && phbmp)
	{
		HBITMAP hbmp = nullptr;
		LPCSTR lpszBitmapPath = PrivacyIDEA::ws2s(_config->bitmapPath).c_str();
		DebugPrint(lpszBitmapPath);
		if (NOT_EMPTY(lpszBitmapPath))
		{
			DWORD const dwAttrib = GetFileAttributesA(lpszBitmapPath);

			DebugPrint(dwAttrib);
			if (dwAttrib != INVALID_FILE_ATTRIBUTES
				&& !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
			{
				hbmp = (HBITMAP)LoadImageA(nullptr, lpszBitmapPath, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

				if (hbmp == nullptr)
				{
					DebugPrint(GetLastError());
				}
			}
		}
		if (hbmp == nullptr)
		{
			// multiOTP/yj
			PWSTR path;
			// If multiotp.bmp exists, use this file
			if (readRegistryValueString(CONF_PATH, &path, L"c:\\multiotp\\") > 1) {
				wchar_t bitmap_path[1024];
				wcscpy_s(bitmap_path, 1024, path);
				size_t npath = wcslen(bitmap_path);
				if (bitmap_path[npath - 1] != '\\' && bitmap_path[npath - 1] != '/') {
					bitmap_path[npath] = '\\';
					bitmap_path[npath + 1] = '\0';
				}
				wcscat_s(bitmap_path, 1024, L"multiotp.bmp");
				if (PathFileExists(bitmap_path)) {
					hbmp = (HBITMAP)LoadImage(HINST_THISDLL, bitmap_path, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
				}
				else {
					hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
				}
			}
			else {
				hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
			}
			// multiOTP/yj
		}

		if (hbmp != nullptr)
		{
			hr = S_OK;
			*phbmp = hbmp;
		}
		else
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrint(hr);

	return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CCredential::GetSubmitButtonValue(
	__in DWORD dwFieldID,
	__out DWORD* pdwAdjacentTo
)
{
	DebugPrint(__FUNCTION__);
	//DebugPrint("Submit Button ID:" + to_string(dwFieldID));
	if (FID_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
	{
		// This is only called once when the credential is created.
		// When switching to the second step, the button is set via CredentialEvents
		*pdwAdjacentTo = _config->twoStepHideOTP ? FID_LDAP_PASS : FID_OTP;
		return S_OK;
	}
	return E_INVALIDARG;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field.
HRESULT CCredential::SetStringValue(
	__in DWORD dwFieldID,
	__in PCWSTR pwz
)
{
	HRESULT hr;

	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
			CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
		CoTaskMemFree(*ppwszStored);
		hr = SHStrDupW(pwz, ppwszStored);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the 
// currently selected item (pdwSelectedItem).
HRESULT CCredential::GetComboBoxValueCount(
	__in DWORD dwFieldID,
	__out DWORD* pcItems,
	__out_range(< , *pcItems) DWORD* pdwSelectedItem
)
{
	DebugPrint(__FUNCTION__);

	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		// UNUSED
		*pcItems = 0;
		*pdwSelectedItem = 0;
		return S_OK;
	}
	else
	{
		return E_INVALIDARG;
	}
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CCredential::GetComboBoxValueAt(
	__in DWORD dwFieldID,
	__in DWORD dwItem,
	__deref_out PWSTR* ppwszItem)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwItem);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszItem);

	return E_INVALIDARG;
}

// Called when the user changes the selected item in the combobox.
HRESULT CCredential::SetComboBoxSelectedValue(
	__in DWORD dwFieldID,
	__in DWORD dwSelectedItem
)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwSelectedItem);
	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		return S_OK;
	}
	else
	{
		return E_INVALIDARG;
	}
}

HRESULT CCredential::GetCheckboxValue(
	__in DWORD dwFieldID,
	__out BOOL* pbChecked,
	__deref_out PWSTR* ppwszLabel
)
{
	// Called to check the initial state of the checkbox
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszLabel);
	*pbChecked = FALSE;
	//SHStrDupW(L"Use offline token.", ppwszLabel); // TODO custom text?

	return S_OK;
}

HRESULT CCredential::SetCheckboxValue(
	__in DWORD dwFieldID,
	__in BOOL bChecked
)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(bChecked);
	DebugPrint(__FUNCTION__);
	return S_OK;
}

//------------- 
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	DebugPrint(__FUNCTION__);
	switch (dwFieldID)
	{
	   case FID_REQUIRE_SMS:
		   if(_pCredProvCredentialEvents) {
			   return multiotp_request(_config->credential.username, L"", L"sms");
		   }
		   break;
	   default:
		   return E_INVALIDARG;
	}
	return S_OK;
}

//------ end of methods for controls we don't have in our tile ----//

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
HRESULT CCredential::GetSerialization(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
	DebugPrint(__FUNCTION__);

	*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;

	HRESULT hr = E_FAIL, retVal = S_OK;

	/*
	CPGSR_NO_CREDENTIAL_NOT_FINISHED
	No credential was serialized because more information is needed.

	CPGSR_NO_CREDENTIAL_FINISHED
	This serialization response means that the Credential Provider has not serialized a credential but
	it has completed its work. This response has multiple meanings.
	It can mean that no credential was serialized and the user should not try again.
	This response can also mean no credential was submitted but the credential?s work is complete.
	For instance, in the Change Password scenario, this response implies success.

	CPGSR_RETURN_CREDENTIAL_FINISHED
	A credential was serialized. This response implies a serialization structure was passed back.

	CPGSR_RETURN_NO_CREDENTIAL_FINISHED
	The credential provider has not serialized a credential, but has completed its work.
	The difference between this value and CPGSR_NO_CREDENTIAL_FINISHED is that this flag
	will force the logon UI to return, which will unadvise all the credential providers.
	*/

	_config->provider.pCredProvCredentialEvents = _pCredProvCredentialEvents;
	_config->provider.pCredProvCredential = this;

	_config->provider.pcpcs = pcpcs;
	_config->provider.pcpgsr = pcpgsr;

	_config->provider.status_icon = pcpsiOptionalStatusIcon;
	_config->provider.status_text = ppwszOptionalStatusText;

	_config->provider.field_strings = _rgFieldStrings;

	// Do password change
	if (_config->credential.passwordMustChange)
	{
		// Compare new passwords
		if (_config->credential.newPassword1 == _config->credential.newPassword2)
		{
			_util.KerberosChangePassword(pcpgsr, pcpcs, _config->credential.username, _config->credential.password,
				_config->credential.newPassword1, _config->credential.domain);
		}
		else
		{
			// not finished
			ShowErrorMessage(L"New passwords don't match!", 0);
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			_config->clearFields = false;
		}
	}
	else if (_config->credential.passwordChanged)
	{
		// Logon with the new password
		hr = _util.KerberosLogon(pcpgsr, pcpcs, _config->provider.cpu,
			_config->credential.username, _config->credential.newPassword1, _config->credential.domain);
		_config->credential.passwordChanged = false;
	}
	else
	{
		if (_config->userCanceled)
		{
			*_config->provider.status_icon = CPSI_ERROR;
			*_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
			SHStrDupW(L"Logon cancelled", _config->provider.status_text);
			return S_FALSE;
		}
		// Check if we are pre 2nd step or failure
		if (_piStatus != PI_AUTH_SUCCESS && _config->pushAuthenticationSuccessful == false)
		{
			if (_config->isSecondStep == false && _config->twoStepHideOTP)
			{
				// Prepare for the second step (input only OTP)
				_config->isSecondStep = true;
				_config->clearFields = false;
				_util.SetScenario(_config->provider.pCredProvCredential,
					_config->provider.pCredProvCredentialEvents,
					SCENARIO::SECOND_STEP);
				*_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
			else
			{
				// Failed authentication or error section
				// Create a message depending on the error
				int errorCode = 0;
				wstring errorMessage;
				bool isGerman = GetUserDefaultUILanguage() == 1031;
				if (_piStatus == PI_AUTH_FAILURE)
				{
					errorMessage = _config->defaultOTPFailureText;
				}
				// In this case the error is contained in a valid response from PI
				else if (_piStatus == PI_AUTH_ERROR)
				{
					errorMessage = _privacyIDEA.getLastErrorMessage();
					errorCode = _privacyIDEA.getLastError();
				}
				else if (_piStatus == PI_WRONG_OFFLINE_SERVER_UNAVAILABLE)
				{
					errorMessage = isGerman ? L"Server nicht erreichbar oder falsches offline OTP!" :
						L"Server unreachable or wrong offline OTP!";
				}
				else if (_piStatus == PI_ENDPOINT_SERVER_UNAVAILABLE)
				{
					errorMessage = isGerman ? L"Server nicht erreichbar!" : L"Server unreachable!";
				}
				else if (_piStatus == PI_ENDPOINT_SETUP_ERROR)
				{
					errorMessage = isGerman ? L"Fehler beim Verbindungsaufbau!" : L"Error while setting up the connection!";
				}
				ShowErrorMessage(errorMessage, errorCode);
				_util.ResetScenario(this, _pCredProvCredentialEvents);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
		}
		else if (_piStatus == PI_AUTH_SUCCESS || _config->pushAuthenticationSuccessful)
		{
			// Reset the authentication
			_piStatus = PI_STATUS_NOT_SET;
			_config->pushAuthenticationSuccessful = false;
			_privacyIDEA.stopPoll();

			// Pack credentials for logon
			if (_config->provider.cpu == CPUS_CREDUI)
			{
				hr = _util.CredPackAuthentication(pcpgsr, pcpcs, _config->provider.cpu,
					_config->credential.username, _config->credential.password, _config->credential.domain);
			}
			else
			{
				hr = _util.KerberosLogon(pcpgsr, pcpcs, _config->provider.cpu,
					_config->credential.username, _config->credential.password, _config->credential.domain);
			}
			if (SUCCEEDED(hr))
			{
				/* if (_config->credential.passwordChanged)
					_config->credential.passwordChanged = false; */
			}
			else
			{
				retVal = S_FALSE;
			}
		}
		else
		{
			ShowErrorMessage(L"Unexpected error", 0);

			// Jump to the first login window
			_util.ResetScenario(this, _pCredProvCredentialEvents);
			retVal = S_FALSE;
		}
	}

	if (_config->clearFields)
	{
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	}
	else
	{
		_config->clearFields = true; // it's a one-timer...
	}

#ifdef _DEBUG
	if (pcpgsr)
	{
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_FINISHED"); }
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_NOT_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_NOT_FINISHED"); }
		if (*pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_CREDENTIAL_FINISHED"); }
		if (*pcpgsr == CPGSR_RETURN_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_NO_CREDENTIAL_FINISHED"); }
	}
	else { DebugPrint("pcpgsr is a nullpointer!"); }
	DebugPrint("CCredential::GetSerialization - END");
#endif //_DEBUG
	return retVal;
}

// if code == 0, the code won't be displayed
void CCredential::ShowErrorMessage(const std::wstring& message, const HRESULT& code)
{
	*_config->provider.status_icon = CPSI_ERROR;
	wstring errorMessage = message;
	if (code != 0) errorMessage += L" (" + to_wstring(code) + L")";
	SHStrDupW(errorMessage.c_str(), _config->provider.status_text);
}

// If push is successful, reset the credential to do autologin
void CCredential::PushAuthenticationCallback(bool success)
{
	DebugPrint(__FUNCTION__);
	if (success)
	{
		_config->pushAuthenticationSuccessful = true;
		_config->doAutoLogon = true;
		// When autologon is triggered, connect is called instantly, therefore bypass privacyIDEA on next run
		_config->bypassPrivacyIDEA = true;
		_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
	}
}

// Connect is called first after the submit button is pressed.
HRESULT CCredential::Connect(__in IQueryContinueWithStatus* pqcws)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(pqcws);

	_config->provider.pCredProvCredential = this;
	_config->provider.pCredProvCredentialEvents = _pCredProvCredentialEvents;
	_config->provider.field_strings = _rgFieldStrings;
	_util.ReadFieldValues();


	// Check if the user is the excluded account
	if (!_config->excludedAccount.empty())
	{
		wstring toCompare;
		if (!_config->credential.domain.empty()) {
			toCompare.append(_config->credential.domain).append(L"\\");
		}
		toCompare.append(_config->credential.username);
		if (PrivacyIDEA::toUpperCase(toCompare) == PrivacyIDEA::toUpperCase(_config->excludedAccount)) {
			DebugPrint("Login data matches excluded account, skipping 2FA...");
			// Simulate 2FA success so the logic in GetSerialization can stay the same
			_piStatus = PI_AUTH_SUCCESS;
			return S_OK;
		}
	}

	if (!_config->excludedAddresses.empty())
	{
		if (Shared::IsRemoteClientAddressExcluded(_config->excludedAddresses))
		{
			DebugPrint("Login client matches excluded address, skipping 2FA...");
			_piStatus = PI_AUTH_SUCCESS;
			return S_OK;
		}
	}

	if (_config->bypassPrivacyIDEA)
	{
		DebugPrint("Bypassing privacyIDEA...");
		_config->bypassPrivacyIDEA = false;

		return S_OK;
	}

	if (_config->twoStepHideOTP && !_config->isSecondStep)
	{
		if (!_config->twoStepSendEmptyPassword && !_config->twoStepSendPassword)
		{
			// Delay for a short moment, otherwise logonui freezes (???)
			this_thread::sleep_for(chrono::milliseconds(200));
			// Then skip to next step
		}
		else
		{
			// Send either empty pass or the windows password in first step
			SecureWString toSend = L"sms";
			if (!_config->twoStepSendEmptyPassword && _config->twoStepSendPassword)
				toSend = _config->credential.password;

			_piStatus = _privacyIDEA.validateCheck(_config->credential.username, _config->credential.domain, toSend);
			if (_piStatus == PI_TRIGGERED_CHALLENGE)
			{
				Challenge c = _privacyIDEA.getCurrentChallenge();
				_config->challenge = c;
				if (!c.transaction_id.empty())
				{
					// Always show the OTP field, if push was triggered, start polling in background
					if (c.tta == TTA::BOTH || c.tta == TTA::PUSH)
					{
						// When polling finishes, pushAuthenticationCallback is invoked with the finialization success value
						_privacyIDEA.asyncPollTransaction(PrivacyIDEA::ws2s(_config->credential.username), c.transaction_id,
							std::bind(&CCredential::PushAuthenticationCallback, this, std::placeholders::_1));
					}
				}
				else
				{
					DebugPrint("Found incomplete challenge: " + c.toString());
				}
			}
			else
			{
				// Only classic OTP available, nothing else to do in the first step
			}
		}
	}
	//////////////////// SECOND STEP ////////////////////////
	else if (_config->twoStepHideOTP && _config->isSecondStep)
	{
		// Send with optional transaction_id from first step
		_piStatus = _privacyIDEA.validateCheck(
			_config->credential.username,
			_config->credential.domain,
			SecureWString(_config->credential.otp.c_str()),
			"");
	}
	//////// NORMAL SETUP WITH 3 FIELDS -> SEND OTP ////////
	else
	{
		_piStatus = _privacyIDEA.validateCheck(
			_config->credential.username,
			_config->credential.domain,
			SecureWString(_config->credential.otp.c_str()),
			"");
	}

	DebugPrint("Connect - END");
	return S_OK; // always S_OK
}

HRESULT CCredential::Disconnect()
{
	return E_NOTIMPL;
}

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CCredential::ReportResult(
	__in NTSTATUS ntsStatus,
	__in NTSTATUS ntsSubstatus,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
#ifdef _DEBUG
	DebugPrint(__FUNCTION__);
	// only print interesting statuses
	if (ntsStatus != 0)
	{
		std::stringstream ss;
		ss << std::hex << ntsStatus;
		DebugPrint("ntsStatus: " + ss.str());
	}
	if (ntsSubstatus != 0)
	{
		std::stringstream ss;
		ss << std::hex << ntsSubstatus;
		DebugPrint("ntsSubstatus: " + ss.str());
	}
#endif

	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	if (_config->credential.passwordMustChange && ntsStatus == 0 && ntsSubstatus == 0)
	{
		// Password change was successful, set this so SetSelected knows to autologon
		_config->credential.passwordMustChange = false;
		_config->credential.passwordChanged = true;
		_util.ResetScenario(this, _pCredProvCredentialEvents);
		return S_OK;
	}

	bool const pwMustChange = (ntsStatus == STATUS_PASSWORD_MUST_CHANGE) || (ntsSubstatus == STATUS_PASSWORD_EXPIRED);
	if (pwMustChange /* && !_config->credential.passwordMustChange*/)
	{
		_config->credential.passwordMustChange = true;
		DebugPrint("Status: Password must change");
		return S_OK;
	}

	// check if the password update was NOT successfull
	// these two are for new passwords not conform to password policies
	bool pwNotUpdated = (ntsStatus == STATUS_PASSWORD_RESTRICTION) || (ntsSubstatus == STATUS_ILL_FORMED_PASSWORD);
	if (pwNotUpdated)
	{
		DebugPrint("Status: Password update failed: Not conform to policies");
	}
	// this catches the wrong old password 
	pwNotUpdated = pwNotUpdated || ((ntsStatus == STATUS_LOGON_FAILURE) && (ntsSubstatus == STATUS_INTERNAL_ERROR));

	if (pwNotUpdated)
	{
		// it wasn't updated so we start over again
		_config->credential.passwordMustChange = true;
		_config->credential.passwordChanged = false;
	}
	/*
	if (ntsStatus == STATUS_LOGON_FAILURE && !pwNotUpdated)
	{
		_util.ResetScenario(this, _pCredProvCredentialEvents);
	}
	*/
	_util.ResetScenario(this, _pCredProvCredentialEvents);
	return S_OK;
}
