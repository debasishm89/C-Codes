#include <windows.h>
__declspec(naked) EvilFunction()
{
          /*
          0007FA18   01001FC4  Ä.  /CALL to MessageBoxW from notepad.01001FBE
          0007FA1C   001503C8  È.  |hOwner = 001503C8 ('Find',class='#32770',parent=003C029E)
          0007FA20   000A3A88  ˆ:..  |Text = "Cannot find "junk""
          0007FA24   000A8F34  4..  |Title = "Notepad"
          0007FA28   00000040  @...  \Style = MB_OK|MB_ICONASTERISK|MB_APPLMODAL
          */                                       
  char Title = "\x4d\x00\x65\x00\x73\x00\x73\x00\x61\x00\x67\x00\x65\x00\x42\x00\x6f\x00\x78\x00\x20\x00\x4f\x00\x77\x00\x6e\x00\x65\x00\x64\x00\x21\x00\x00";   
  int sizeTitle = 31;
   __asm("movl %eax,0x10(%ebp)");    
   __asm("pop %eax");  
   __asm("popf");           
   __asm("mov %edi,%edi");          
   __asm("push %ebp");
   __asm("mov %ebp,%esp");   
   __asm("nop");               
   __asm("nop");               
   __asm("nop");               
   __asm("nop");               
   __asm("nop");                               
   __asm("nop");   
   __asm("nop");               
   __asm("nop");               
   __asm("nop");               
   __asm("nop");
/*
6BA011D0   9C               PUSHFD
6BA011D1   8BEC             MOV EBP,ESP
6BA011D3   83EC 08          SUB ESP,8
6BA011D6   B8 0030A06B      MOV EAX,Inline.6BA03000                  ; UNICODE "MessageBox Owned!"
6BA011DB   8845 FF          MOV BYTE PTR SS:[EBP-1],AL
6BA011DE   C745 F8 1F000000 MOV DWORD PTR SS:[EBP-8],1F
6BA011E5   8945 10          MOV DWORD PTR SS:[EBP+10],EAX
6BA011E8   58               POP EAX
6BA011E9   9D               POPFD
6BA011EA   89FF             MOV EDI,EDI
6BA011EC   55               PUSH EBP
6BA011ED   89EC             MOV ESP,EBP
6BA011EF   90               NOP
6BA011F0   90               NOP
6BA011F1   90               NOP
6BA011F2   90               NOP
6BA011F3   90               NOP
6BA011F4  -E9 224F390C      JMP USER32.77D9611B
*/
}

BOOL APIENTRY DllMain (HINSTANCE hInst,DWORD reason,LPVOID reserved)     
{
char  jmp[1] = "\xE9";  
char  nops[5] = "\x90\x90\x90\x90\x90"; 
char  stacksetup[3] = "\x9C\x8B\xEC";  
HMODULE HandleModule;
DWORD null  = 0;
    switch (reason)
    {
      case DLL_PROCESS_ATTACH:
		  HandleModule = GetModuleHandle(TEXT("user32.dll"));                                      
		  DWORD MessageBoxAddress = GetProcAddress(HandleModule,"MessageBoxW"); 
          /*
          0007FA18   01001FC4  Ä.  /CALL to MessageBoxW from notepad.01001FBE
          0007FA1C   001503C8  È.  |hOwner = 001503C8 ('Find',class='#32770',parent=003C029E)
          0007FA20   000A3A88  ˆ:..  |Text = "Cannot find "junk""
          0007FA24   000A8F34  4..  |Title = "Notepad"
          0007FA28   00000040  @...  \Style = MB_OK|MB_ICONASTERISK|MB_APPLMODAL
          */                                       
		  DWORD EvilFunctionPointer = (LPDWORD)&EvilFunction;                                                
		  memcpy(nops,MessageBoxAddress,0x5);                                                     
		  DWORD longjump = EvilFunctionPointer - MessageBoxAddress;                                             
		  DWORD jumpland = longjump - 5;                                                          
		  VirtualProtect(MessageBoxAddress,0x8,PAGE_READWRITE,&null);                           
		  memcpy(MessageBoxAddress,jmp,0x1);                                                        
		  memcpy(MessageBoxAddress+1,&jumpland,0x4);                                                 
		  VirtualProtect(MessageBoxAddress,0x8,PAGE_EXECUTE_READ,&null); 
		  VirtualProtect(EvilFunctionPointer,0x3,PAGE_READWRITE,&null);      
		  memcpy(EvilFunctionPointer,stacksetup,0x3);                              
		  VirtualProtect(EvilFunctionPointer,0x3,PAGE_EXECUTE_READ,&null);   
		  DWORD jumptoloc = EvilFunctionPointer + 0x24;                       
		  DWORD jumplength = MessageBoxAddress + 0x5;                              
		  DWORD distance = jumplength - jumptoloc - 0x5;
		  VirtualProtect(jumptoloc,0x8,PAGE_READWRITE,&null);         
		  memcpy(jumptoloc,jmp,0x1);                                    
		  memcpy(jumptoloc+1,&distance,0x4);    
		  VirtualProtect(jumptoloc,0x8,PAGE_EXECUTE_READ,&null);
      break;
    }
    return TRUE;
}
