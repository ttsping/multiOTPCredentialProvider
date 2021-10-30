/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2020 NetKnights GmbH
** Author: Nils Behlen
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

#pragma once
#include <credentialprovider.h>
#include <string>
/* Methods that are used by both the CredentialProvider and the Filter */
namespace Shared
{
#define PROVIDER 0
#define FILTER 1

	template<typename StringT, typename ContainerT>
	ContainerT& SplitString(const StringT& in, ContainerT& out, const std::wstring& delimiters) {
		size_t pos = 0;
		size_t lastPos = 0;
		do {
			size_t len = 0;
			pos = in.find(delimiters, lastPos);
			if (pos == StringT::npos) {
				len = in.size() - lastPos;
			}
			else {
				len = pos - lastPos;
			}
			if (len != 0) {
				out.push_back(in.substr(lastPos, len));
			}
			lastPos = pos + 1;
		} while (pos != StringT::npos);
		return out;
	}

	bool IsRequiredForScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, int caller);

	bool IsCurrentSessionRemote();

	std::string CPUStoString(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus);

	bool IsRemoteClientAddressExcluded(const std::wstring& configExcludeAddress);
};

