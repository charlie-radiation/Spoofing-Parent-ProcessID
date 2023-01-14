#define _WIN32_WINNT 0x0600
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

using namespace std;

DWORD get_pid_0x7_Alpha() {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);

	if (Process32First(snapshot, &pe))
	{
		do {
        
			if (stricmp(pe.szExeFile, "notepad.exe") == 0)
				break;
		} while (Process32Next(snapshot, &pe));
	}

	CloseHandle(snapshot);
	return pe.th32ProcessID;
}

DWORD get_pid_0x7_Bravo() {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);

	if (Process32First(snapshot, &pe)) {
		do {
            	
				if (stricmp(pe.szExeFile, "WINWORD.exe") == 0)
				break;
		} while (Process32Next(snapshot, &pe));
	}

	CloseHandle(snapshot);
	return pe.th32ProcessID;
}


DWORD get_pid_0x7_charlie() {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(pe);

	if (Process32First(snapshot, &pe)) {
		do {
       	if (stricmp(pe.szExeFile, "mspaint.exe") == 0)
				break;
		} while (Process32Next(snapshot, &pe));
	}

	CloseHandle(snapshot);
	return pe.th32ProcessID;
}


DWORD get_pid_0x7_tango() {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize =  sizeof(pe);

	if (Process32First(snapshot, &pe))
	{
		do {
       	if (stricmp(pe.szExeFile, "SnippingTool.exe") == 0)
				break;
		} while (Process32Next(snapshot, &pe));
	}

	CloseHandle(snapshot);
	return pe.th32ProcessID;
}


DWORD inj_0x7_Alpha(int)
{
	
	STARTUPINFOEXA s_info;
	PROCESS_INFORMATION p_info;
	SIZE_T attribute_Size;
	ZeroMemory(&s_info, sizeof(STARTUPINFOEXA));
	
	HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, get_pid_0x7_Alpha()); 

	InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_Size);
	s_info.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attribute_Size);
	InitializeProcThreadAttributeList(s_info.lpAttributeList, 1, 0, &attribute_Size);
	UpdateProcThreadAttribute(s_info.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
	
	s_info.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &s_info.StartupInfo, &p_info);

	return 0;
}

DWORD inj_0x7_Bravo(int)
{
	 
	STARTUPINFOEXA s_info;
	PROCESS_INFORMATION p_info;
	SIZE_T attribute_Size;
	ZeroMemory(&s_info, sizeof(STARTUPINFOEXA));
	
	HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, get_pid_0x7_Bravo()); 

	InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_Size);
	s_info.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attribute_Size);
	InitializeProcThreadAttributeList(s_info.lpAttributeList, 1, 0, &attribute_Size);
	UpdateProcThreadAttribute(s_info.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
	s_info.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &s_info.StartupInfo, &p_info);

	return 0;
}


DWORD inj_0x7_charlie(int)
{
	 
	STARTUPINFOEXA s_info;
	PROCESS_INFORMATION p_info;
	SIZE_T attribute_Size;
	ZeroMemory(&s_info, sizeof(STARTUPINFOEXA));
	
	HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, get_pid_0x7_Bravo()); 

	InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_Size);
	s_info.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attribute_Size);
	InitializeProcThreadAttributeList(s_info.lpAttributeList, 1, 0, &attribute_Size);
	UpdateProcThreadAttribute(s_info.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
		s_info.StartupInfo.cb =  sizeof(STARTUPINFOEXA);

	CreateProcessA(NULL, (LPSTR)"calc", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &s_info.StartupInfo, &p_info);

	return 0;
}


DWORD inj_0x7_tango(int)
{
	 
	STARTUPINFOEXA s_info;
	PROCESS_INFORMATION p_info;
	SIZE_T attribute_Size;
	ZeroMemory(&s_info, sizeof(STARTUPINFOEXA));
	
	HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, get_pid_0x7_Bravo()); 

	InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_Size);
	s_info.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attribute_Size);
	InitializeProcThreadAttributeList(s_info.lpAttributeList, 1, 0, &attribute_Size);
	UpdateProcThreadAttribute(s_info.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
	s_info.StartupInfo.cb =  sizeof(STARTUPINFOEXA);

	CreateProcessA(NULL, (LPSTR)"dxdiag", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &s_info.StartupInfo, &p_info);

	return 0;
}



int main() 
{
	system("Color 0A");
	
	    cout << "|============================= cH@rL!3.xRad!+!0n ===============================|" << endl;  
        cout << "|===============================================================================|" << endl;  
        cout << "|                             Program Description                               |" << endl;  
        cout << "|                         Sp00f!ng Parent Process !d                            |" << endl;  
        cout << "|===============================================================================|" << endl;  
        cout << "|============================= Abdullah Awais ==================================|" << endl;  
        cout << "|===============================================================================|" << endl;  
        cout << "" << endl;
		cout << "" << endl;
		cout << "" << endl;
		cout << "" << endl;
	
	cout <<"\n +------ [PID] Notepad  :" << get_pid_0x7_Alpha() << endl;
	cout <<"\n +------ [PID] Spoofed Process ID  :" << inj_0x7_Alpha(get_pid_0x7_Alpha())<< endl;
	cout << "\n" << endl;
		
	cout <<"\n +------ [PID] MS Word  :" << get_pid_0x7_Bravo() << endl;
	cout <<"\n +------ [PID] Spoofed Process ID  :" << inj_0x7_Bravo(get_pid_0x7_Bravo())<< endl;
	cout << "\n" << endl;
	
	
	cout <<"\n +------ [PID] MS Paint :" << get_pid_0x7_charlie() << endl;
	cout <<"\n +------ [PID] Spoofed Process ID  :" << inj_0x7_charlie(get_pid_0x7_charlie())<< endl;
	cout << "\n" << endl;
	
	cout <<"\n +------ [PID] MS Paint :" << get_pid_0x7_tango() << endl;
	cout <<"\n +------ [PID] Spoofed Process ID  :" << inj_0x7_tango(get_pid_0x7_tango())<< endl;
	cout << "\n" << endl;
}
