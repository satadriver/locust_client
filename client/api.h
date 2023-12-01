#pragma once

#include <windows.h>
#include <lmcons.h>
#include <TlHelp32.h>

#include <winhttp.h>

typedef UINT(__stdcall *ptrGetSystemDirectoryA)(LPSTR, DWORD);
typedef HANDLE(__stdcall * ptrGetCurrentProcess)();
typedef FARPROC(__stdcall *ptrGetProcAddress)(HMODULE, LPSTR);
typedef HMODULE(__stdcall *ptrLoadLibraryA)(LPSTR);

typedef DWORD(__stdcall* ptrGetTickCount)(VOID);

typedef ULONGLONG(__stdcall* ptrGetTickCount64)(VOID);

typedef DWORD(__stdcall *ptrFreeLibrary)(HMODULE);

typedef HMODULE(__stdcall *ptrGetModuleHandleA)(LPSTR);
typedef DWORD(__stdcall *ptrWinExec)(LPSTR, DWORD);

typedef DWORD(__stdcall *ptrSetCurrentDirectoryA)(_In_ LPCSTR lpPathName);
typedef DWORD(__stdcall *ptrGetUserNameA)(LPSTR lpBuffer, _Inout_ LPDWORD pcbBuffer);
typedef DWORD(__stdcall *ptrGetComputerNameA)(LPSTR lpBuffer, _Inout_ LPDWORD nSize);

typedef LPSTR(__stdcall *ptrVirtualAlloc)(char*, DWORD, DWORD, DWORD);
typedef UINT(__stdcall *ptrVirtualFree)(LPVOID, DWORD, DWORD);
typedef DWORD(WINAPI * ptrNetWkstaGetInfo)(__in_opt IN LMSTR servername OPTIONAL, IN DWORD level, LPBYTE*);
typedef DWORD(WINAPI * ptrNetApiBufferFree)(IN LPVOID Buffer);

typedef LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI* ptrSetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);

typedef HANDLE(WINAPI* ptrCreateToolhelp32Snapshot)(DWORD dwFlags,DWORD th32ProcessID);

typedef BOOL (WINAPI* ptrProcess32FirstW)(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);

typedef BOOL (WINAPI* ptrProcess32NextW)(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);

typedef HANDLE(WINAPI* ptrOpenProcess)(DWORD dwDesiredAccess,BOOL  bInheritHandle,DWORD dwProcessId);

typedef BOOL(WINAPI* ptrOpenProcessToken)(HANDLE  ProcessHandle, DWORD   DesiredAccess,PHANDLE TokenHandle);

typedef BOOL(__stdcall *ptrVirtualProtect)(
	__in  LPVOID lpAddress,
	__in  SIZE_T dwSize,
	__in  DWORD flNewProtect,
	__out PDWORD lpflOldProtect
);

typedef HINSTANCE(__stdcall *ptrShellExecuteA)(
	HWND hwnd,
	LPCSTR lpOperation,
	LPCSTR lpFile,
	LPCSTR lpParameters,
	LPCSTR lpDirectory,
	INT nShowCmd);

typedef wchar_t ** (__stdcall *ptrCommandLineToArgvW)(__in LPCWSTR lpCmdLine, __out int* pNumArgs);
typedef LPCWSTR(__stdcall *ptrGetCommandLineW)();

typedef int (__fastcall *ptrMakeSureDirectoryPathExists)(LPSTR);

typedef BOOL(__fastcall* ptrContinueDebugEvent)(DWORD dwProcessId,DWORD dwThreadId,DWORD dwContinueStatus);


typedef HANDLE(__stdcall* ptrCreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCSTR lpName);

typedef BOOL (__stdcall * ptrCloseHandle)(HANDLE hObject);

typedef BOOL(__stdcall* ptrIsDebuggerPresent)();

typedef DWORD(__stdcall* ptrGetCurrentProcessId)();

typedef BOOL(__stdcall* ptrDebugActiveProcess)(DWORD dwProcessId);

typedef DWORD(__stdcall* ptrWaitForSingleObject)(
	_In_ HANDLE hHandle,
	_In_ DWORD dwMilliseconds
);

typedef BOOL(__stdcall* ptrCheckRemoteDebuggerPresent)(
	_In_ HANDLE hProcess,
	_Out_ PBOOL pbDebuggerPresent
);

typedef BOOL(__stdcall* ptrSHGetSpecialFolderPathA)(HWND  hwnd,LPSTR pszPath,int   csidl,BOOL  fCreate);

typedef VOID (__stdcall* ptrGetNativeSystemInfo)(
	_Out_ LPSYSTEM_INFO lpSystemInfo
);

typedef BOOL(__stdcall* ptrCreateEnvironmentBlock)(LPVOID* lpEnvironment,HANDLE  hToken,BOOL    bInherit);

typedef BOOL(__stdcall* ptrDestroyEnvironmentBlock)(LPVOID  lpEnvironment);

typedef HANDLE(__stdcall* ptrCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,
LPTHREAD_START_ROUTINE  lpStartAddress,
LPVOID lpParameter,
DWORD                   dwCreationFlags,
LPDWORD                 lpThreadId
);

typedef HANDLE(__stdcall* ptrCreateFileA)(
 LPCSTR                lpFileName,
DWORD                 dwDesiredAccess,
DWORD                 dwShareMode,
LPSECURITY_ATTRIBUTES lpSecurityAttributes,
 DWORD                 dwCreationDisposition,
DWORD                 dwFlagsAndAttributes,
HANDLE                hTemplateFile
);


typedef BOOL(__stdcall* ptrWaitForDebugEvent)(LPDEBUG_EVENT lpDebugEvent,DWORD         dwMilliseconds);

typedef void(__stdcall* ptrSleep)(DWORD dwMilliseconds);

typedef  BOOL(__stdcall* ptrCreateProcessAsUserA)(
	_In_opt_ HANDLE hToken,
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL(__stdcall* ptrCreateProcessW)(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
);

typedef  DWORD(__stdcall* ptrGetFileSize)(HANDLE hFile,LPDWORD lpFileSizeHigh);

typedef DWORD(__stdcall* ptrSetFilePointer)(
	_In_ HANDLE hFile,
	_In_ LONG lDistanceToMove,
	_Inout_opt_ PLONG lpDistanceToMoveHigh,
	_In_ DWORD dwMoveMethod
);


typedef HANDLE (__stdcall* ptrFindFirstFileA)(
	_In_ LPCSTR lpFileName,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
);


typedef BOOL(__stdcall* ptrFindNextFileA)(
	_In_ HANDLE hFindFile,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
);


typedef BOOL(__stdcall* ptrFindClose)(
	_Inout_ HANDLE hFindFile
);

typedef BOOL (__stdcall* ptrSetFileAttributesA)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwFileAttributes
);

typedef BOOL(__stdcall* ptrWriteFile)(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

typedef BOOL(__stdcall* ptrFlushFileBuffers)(
	_In_ HANDLE hFile
);


typedef BOOL(__stdcall* ptrReadFile)(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

typedef LSTATUS (__stdcall* ptrRegSetValueExA)(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpValueName,
	_Reserved_ DWORD Reserved,
	_In_ DWORD dwType,
	_In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
	_In_ DWORD cbData
);

typedef LSTATUS
(__stdcall* ptrRegCloseKey)(
	_In_ HKEY hKey
);

typedef LSTATUS(__stdcall* ptrRegCreateKeyExA)(
	_In_ HKEY hKey,
	_In_ LPCSTR lpSubKey,
	_Reserved_ DWORD Reserved,
	_In_opt_ LPSTR lpClass,
	_In_ DWORD dwOptions,
	_In_ REGSAM samDesired,
	_In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_Out_ PHKEY phkResult,
	_Out_opt_ LPDWORD lpdwDisposition
);

typedef LSTATUS (__stdcall* ptrRegQueryValueExA)(
	_In_ HKEY hKey,
	_In_opt_ LPCSTR lpValueName,
	_Reserved_ LPDWORD lpReserved,
	_Out_opt_ LPDWORD lpType,
	_Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
	_When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
);



typedef VOID(__stdcall* ptrExitProcess)(
	_In_ UINT uExitCode
);

typedef  BOOL(__stdcall* ptrTerminateProcess)(
	_In_ HANDLE hProcess,
	_In_ UINT uExitCode
);



typedef int (__stdcall* ptrWSAStartup)(
	_In_ WORD wVersionRequired,
	_Out_ LPWSADATA lpWSAData);

typedef DWORD(__stdcall* ptrsend)(SOCKET, char*, DWORD, DWORD);
typedef DWORD(__stdcall* ptrrecv)(SOCKET, char*, DWORD, DWORD);
typedef DWORD(__stdcall* ptrclosesocket)(SOCKET);
typedef DWORD(__stdcall* ptrconnect)(SOCKET, sockaddr*, DWORD);
typedef DWORD(__stdcall* ptrinet_addr)(char*);
typedef unsigned short(__stdcall* ptrntohs)(unsigned short);
typedef DWORD(__stdcall* ptrgethostname)(char*, int);
typedef SOCKET(__stdcall* ptrsocket)(UINT, UINT, UINT);
typedef hostent* (__stdcall* ptrgethostbyname)(char*);
typedef int(__stdcall* ptrsetsockopt)(__in SOCKET s, __in int level, __in int optname, __in_bcount_opt(optlen) const char FAR* optval, __in int optlen);



typedef HINTERNET(__stdcall* ptrWinHttpOpen)(
	_In_opt_z_ LPCWSTR pszAgentW,
	_In_ DWORD dwAccessType,
	_In_opt_z_ LPCWSTR pszProxyW,
	_In_opt_z_ LPCWSTR pszProxyBypassW,
	_In_ DWORD dwFlags
);

typedef BOOL(__stdcall* ptrWinHttpCloseHandle)
(
	IN HINTERNET hInternet
);

typedef HINTERNET(__stdcall* ptrWinHttpConnect)(
	IN HINTERNET hSession,
	IN LPCWSTR pswzServerName,
	IN INTERNET_PORT nServerPort,
	IN DWORD dwReserved
);


typedef BOOL(__stdcall* ptrWinHttpReadData)(
	IN HINTERNET hRequest,
	_Out_writes_bytes_to_(dwNumberOfBytesToRead, *lpdwNumberOfBytesRead) __out_data_source(NETWORK) LPVOID lpBuffer,
	IN DWORD dwNumberOfBytesToRead,
	OUT LPDWORD lpdwNumberOfBytesRead
);


typedef HINTERNET(__stdcall* ptrWinHttpOpenRequest)(
	IN HINTERNET hConnect,
	IN LPCWSTR pwszVerb,
	IN LPCWSTR pwszObjectName,
	IN LPCWSTR pwszVersion,
	IN LPCWSTR pwszReferrer OPTIONAL,
	IN LPCWSTR FAR* ppwszAcceptTypes OPTIONAL,
	IN DWORD dwFlags
);

typedef BOOL(__stdcall* ptrWinHttpAddRequestHeaders)(
	IN HINTERNET hRequest,
	_When_(dwHeadersLength == (DWORD)-1, _In_z_)
	_When_(dwHeadersLength != (DWORD)-1, _In_reads_(dwHeadersLength))
	LPCWSTR lpszHeaders,
	IN DWORD dwHeadersLength,
	IN DWORD dwModifiers
);

typedef VOID(__stdcall* ptrOutputDebugStringA)(
	_In_opt_ LPCSTR lpOutputString
);

typedef VOID (__stdcall* ptrOutputDebugStringW)(
	_In_opt_ LPCWSTR lpOutputString
);

typedef BOOL(__stdcall* ptrWinHttpSetOption)(HINTERNET hInternet,DWORD     dwOption,LPVOID    lpBuffer, DWORD     dwBufferLength
);


typedef BOOL (__stdcall* ptrWinHttpSendRequest)
(
	IN HINTERNET hRequest,
	_In_reads_opt_(dwHeadersLength) LPCWSTR lpszHeaders,
	IN DWORD dwHeadersLength,
	_In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,
	IN DWORD dwOptionalLength,
	IN DWORD dwTotalLength,
	IN DWORD_PTR dwContext
);

typedef BOOL (__stdcall* ptrWinHttpWriteData)
(
	IN HINTERNET hRequest,
	_In_reads_bytes_opt_(dwNumberOfBytesToWrite) LPCVOID lpBuffer,
	IN DWORD dwNumberOfBytesToWrite,
	OUT LPDWORD lpdwNumberOfBytesWritten
);


typedef void (__stdcall* ptrWinHttpSetStatusCallback)
(
	IN HINTERNET hInternet,
	IN WINHTTP_STATUS_CALLBACK lpfnInternetCallback,
	IN DWORD dwNotificationFlags,
	IN DWORD_PTR dwReserved
);

typedef BOOL(__stdcall* ptrWinHttpReceiveResponse)
(
	IN HINTERNET hRequest,
	IN LPVOID lpReserved
);

typedef BOOL (__stdcall* ptrWinHttpQueryDataAvailable)
(
	IN HINTERNET hRequest,
	__out_data_source(NETWORK) LPDWORD lpdwNumberOfBytesAvailable
);



typedef HCERTSTORE(__stdcall* ptrPFXImportCertStore)(
	_In_ CRYPT_DATA_BLOB* pPFX,
	_In_ LPCWSTR szPassword,
	_In_ DWORD   dwFlags);


typedef PCCERT_CONTEXT(__stdcall* ptrCertEnumCertificatesInStore)(
	_In_ HCERTSTORE hCertStore,
	_In_opt_ PCCERT_CONTEXT pPrevCertContext
);


typedef PCCERT_CONTEXT(__stdcall* ptrCertDuplicateCertificateContext)(
	_In_opt_ PCCERT_CONTEXT pCertContext
);


typedef BOOL(__stdcall* ptrCertCloseStore)(
	_In_opt_ HCERTSTORE hCertStore,
	_In_ DWORD dwFlags
);


typedef BOOL(__stdcall* ptrCertFreeCertificateContext)(
	_In_opt_ PCCERT_CONTEXT pCertContext
);


typedef HRESULT (__stdcall* ptrCoInitializeEx)(
	_In_opt_ LPVOID pvReserved,
	_In_ DWORD dwCoInit
);

typedef HRESULT(__stdcall* ptrCoInitializeSecurity)(
	_In_opt_ PSECURITY_DESCRIPTOR pSecDesc,
	_In_ LONG cAuthSvc,
	_In_reads_opt_(cAuthSvc) SOLE_AUTHENTICATION_SERVICE* asAuthSvc,
	_In_opt_ void* pReserved1,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ void* pAuthList,
	_In_ DWORD dwCapabilities,
	_In_opt_ void* pReserved3
);

typedef void(__stdcall* ptrCoUninitialize)();

typedef HRESULT(__stdcall* ptrCoSetProxyBlanket)(
	_In_ IUnknown* pProxy,
	_In_ DWORD dwAuthnSvc,
	_In_ DWORD dwAuthzSvc,
	_In_opt_ OLECHAR* pServerPrincName,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	_In_ DWORD dwCapabilities
);

typedef HRESULT(__stdcall* ptrCoCreateInstance)(
	_In_ REFCLSID rclsid,
	_In_opt_ LPUNKNOWN pUnkOuter,
	_In_ DWORD dwClsContext,
	_In_ REFIID riid,
	_COM_Outptr_ _At_(*ppv, _Post_readable_size_(_Inexpressible_(varies))) LPVOID  FAR* ppv
);


extern ptrCoCreateInstance			lpCoCreateInstance;
extern ptrCoInitializeEx			lpCoInitializeEx;
extern ptrCoInitializeSecurity		lpCoInitializeSecurity;
extern ptrCoSetProxyBlanket			lpCoSetProxyBlanket;
extern ptrCoUninitialize			lpCoUninitialize;


extern ptrPFXImportCertStore				lpPFXImportCertStore;
extern ptrCertEnumCertificatesInStore		lpCertEnumCertificatesInStore;
extern ptrCertDuplicateCertificateContext	lpCertDuplicateCertificateContext;
extern ptrCertCloseStore					lpCertCloseStore;
extern ptrCertFreeCertificateContext		lpCertFreeCertificateContext;

extern ptrWinHttpSetStatusCallback	lpWinHttpSetStatusCallback;
extern ptrWinHttpQueryDataAvailable	lpWinHttpQueryDataAvailable;
extern ptrWinHttpReceiveResponse		lpWinHttpReceiveResponse;
extern ptrWinHttpWriteData				lpWinHttpWriteData;
extern ptrWinHttpSendRequest			lpWinHttpSendRequest;
extern ptrWinHttpSetOption				lpWinHttpSetOption;
extern ptrWinHttpOpenRequest			lpWinHttpOpenRequest;
extern ptrWinHttpReadData				lpWinHttpReadData;
extern ptrWinHttpAddRequestHeaders		lpWinHttpAddRequestHeaders;
extern ptrWinHttpConnect				lpWinHttpConnect;
extern ptrWinHttpCloseHandle			lpWinHttpCloseHandle;
extern ptrWinHttpOpen					lpWinHttpOpen;

extern ptrCheckRemoteDebuggerPresent	lpCheckRemoteDebuggerPresent;

extern ptrWSAStartup				lpWSAStartup;
extern ptrWSAStartup			lpWSAStartup;
extern ptrsend					lpsend;
extern ptrrecv					lprecv;
extern ptrclosesocket			lpclosesocket;
extern ptrconnect				lpconnect;
extern ptrinet_addr				lpinet_addr;
extern ptrntohs					lpntohs;
extern ptrgethostname			lpgethostname;
extern ptrsocket				lpsocket;
extern ptrgethostbyname			lpgethostbyname;
extern ptrsetsockopt			lpsetsockopt;

extern ptrOutputDebugStringW	lpOutputDebugStringW;
extern ptrOutputDebugStringA	lpOutputDebugStringA;

extern ptrTerminateProcess			lpTerminateProcess;
extern ptrExitProcess				lpExitProcess;

extern ptrFindNextFileA		lpFindNextFileA;
extern ptrFindFirstFileA		lpFindFirstFileA;
extern ptrFindClose			lpFindClose;

extern ptrSHGetSpecialFolderPathA			lpSHGetSpecialFolderPathA;

extern ptrCreateEnvironmentBlock		lpCreateEnvironmentBlock;

extern ptrDestroyEnvironmentBlock		lpDestroyEnvironmentBlock;


extern ptrGetNativeSystemInfo			lpGetNativeSystemInfo;
extern ptrWaitForSingleObject			lpWaitForSingleObject;

extern ptrRegSetValueExA				lpRegSetValueExA;
extern ptrRegCreateKeyExA				lpRegCreateKeyExA;
extern ptrRegCloseKey					lpRegCloseKey;
extern ptrRegQueryValueExA				lpRegQueryValueExA;

extern ptrReadFile				lpReadFile;
extern ptrFlushFileBuffers		lpFlushFileBuffers;
extern ptrWriteFile				lpWriteFile;
extern ptrGetFileSize			lpGetFileSize;
extern ptrSetFilePointer		lpSetFilePointer;
extern ptrSetFileAttributesA	lpSetFileAttributesA;

extern ptrCreateProcessW lpCreateProcessW;

extern ptrCreateProcessAsUserA lpCreateProcessAsUserA;

extern ptrOpenProcess lpOpenProcess;

extern ptrOpenProcessToken lpOpenProcessToken;

extern ptrCreateToolhelp32Snapshot  lpCreateToolhelp32Snapshot;

extern ptrProcess32FirstW lpProcess32FirstW;

extern ptrProcess32NextW lpProcess32NextW;

extern ptrSetUnhandledExceptionFilter lpSetUnhandledExceptionFilter;

extern ptrSleep					lpSleep;

extern ptrGetTickCount	lpGetTickCount;

extern ptrGetTickCount64 lpGetTickCount64;

extern ptrCreateFileA			lpCreateFileA;
extern ptrContinueDebugEvent	lpContinueDebugEvent;

extern ptrDebugActiveProcess	lpDebugActiveProcess;
extern ptrWaitForDebugEvent		lpWaitForDebugEvent;
extern ptrCreateThread			lpCreateThread;
extern ptrGetCurrentProcessId	lpGetCurrentProcessId;
extern ptrGetCurrentProcess		lpGetCurrentProcess;
extern ptrCreateMutexA			lpCreateMutexA;

extern ptrIsDebuggerPresent			lpIsDebuggerPresent;

extern ptrCloseHandle			lpCloseHandle;

extern ptrGetProcAddress		lpGetProcAddress;
extern ptrLoadLibraryA			lpLoadLibraryA;
extern ptrFreeLibrary			lpFreeLibrary;

extern ptrShellExecuteA			lpShellExecuteA;
extern ptrGetCommandLineW						lpGetCommandLineW;
extern ptrCommandLineToArgvW					lpCommandLineToArgvW;

extern ptrMakeSureDirectoryPathExists			lpMakeSureDirectoryPathExists;

extern ptrGetUserNameA							lpGetUserNameA;
extern ptrGetComputerNameA						lpGetComputerNameA;
extern ptrNetWkstaGetInfo						lpNetWkstaGetInfo;
extern ptrNetApiBufferFree						lpNetApiBufferFree;
extern ptrGetSystemDirectoryA					lpGetSystemDirectoryA;
extern ptrWinExec								lpWinExec;
extern ptrGetModuleHandleA						lpGetModuleHandleA;
extern ptrVirtualAlloc							lpVirtualAlloc;
extern ptrVirtualFree							lpVirtualFree;
extern ptrVirtualProtect						lpVirtualProtect;

int getapi();

void testapi();