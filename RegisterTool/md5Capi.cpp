//////////////////////////////////////////////////////////////////////
// md5Capi.cpp: implementation of the Cmd5Capi class.
// Calcule MD5 Digest using the WIN Crypto API.
//
//////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "md5Capi.h"
#include <Iphlpapi.h>
#include <Assert.h>
#pragma comment(lib, "iphlpapi.lib")

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

Cmd5Capi::Cmd5Capi()
{
	csDigest.Empty();
}

Cmd5Capi::Cmd5Capi(CString & csBuffer)
{
	Digest(csBuffer);
}



Cmd5Capi::~Cmd5Capi()
{

}

CString &Cmd5Capi::GetDigest(void)
{
	return csDigest; 

}

CString Cmd5Capi::GetMacAddress()
{
	CString info;
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = (char*)malloc(18);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		free(mac_addr);
		return info; // it is safe to call free(NULL)
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			free(mac_addr);
			return info;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			// technically should look at pAdapterInfo->AddressLength
			//   and not assume it is 6.
			sprintf(mac_addr, "%02X%02X%02X%02X%02X%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			printf("Address: %s, mac: %s\n", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);
			// print them all, return the last one.
			// return mac_addr;

			printf("\n");
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);
	info = mac_addr;
	free(mac_addr);
	return info;
}

CString Cmd5Capi::GetGuidString()
{
	GUID guid;
	HRESULT hCreateGuid = CoCreateGuid(&guid);
	char guidStr[37];
	sprintf_s(
		guidStr,
		"%08lX%04hX%04hX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

	return CString(guidStr);
}


CString &Cmd5Capi::Digest(CString & csBuffer)
{
    HCRYPTPROV hCryptProv; 
    HCRYPTHASH hHash; 
    BYTE bHash[0x7f]; 
    DWORD dwHashLen= 16; // The MD5 algorithm always returns 16 bytes. 
    DWORD cbContent= csBuffer.GetLength(); 
    BYTE* pbContent= (BYTE*)csBuffer.GetBuffer(cbContent); 


    if(CryptAcquireContext(&hCryptProv, 
		NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)) 
	{

		if(CryptCreateHash(hCryptProv, 
			CALG_MD5,	// algorithm identifier definitions see: wincrypt.h
			0, 0, &hHash)) 
		{
			if(CryptHashData(hHash, pbContent, cbContent, 0))
			{

				if(CryptGetHashParam(hHash, HP_HASHVAL, bHash, &dwHashLen, 0)) 
				{
					// Make a string version of the numeric digest value
					csDigest.Empty();
					CString tmp;
					  for (int i = 0; i<16; i++)
					  {
						tmp.Format(L"%02x", bHash[i]);
						csDigest+=tmp;
					  }

				}
				else csDigest=_T("Error getting hash param"); 

			}
			else csDigest=_T("Error hashing data"); 
		}
		else csDigest=_T("Error creating hash"); 

    }
    else csDigest=_T("Error acquiring context"); 


    CryptDestroyHash(hHash); 
    CryptReleaseContext(hCryptProv, 0); 
	csBuffer.ReleaseBuffer();
    return csDigest; 


}
