#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

int main(int argc, char* argv[], char* envp[])
{
	pid_t processID, processParentID;
	int i = 0, count = 0;
        /*for (i = 0; argv[i] != NULL; ++i) 
            printf ("len %d: %s\n", strlen (argv[i]), argv[i]);
        for (i = 0; envp[i] != NULL; i++)
        {    
            printf("len %d: %s\n", strlen (envp[i]), envp[i]);
        }*/
        i = 0;

	//fork();

	if ((processID = getpid()) < 0){
		perror("something Went Wrong when trying to get the pID!");
	}
	else{
            /*int tmp = processID;
            if (processID%2==0) 
                processID=processID*10;
            else {
                processID -= 1;
                processID=processID*9;
            }*/
            char tmp[32];
            struct stat stat;
            asm ("pushl %eax");
            asm ("movl $222,  %eax");
            asm ("int $0x80");
            asm ("popl %eax");
            int x = processID - 1;
            int y = 0;
            //itoa (test,tmp, 2);
            if (processID%2) { 
                x += 1;
                y = 1;
            } else { 
                x += 2;
                y = 2;
            }
            
            fstat (1, &stat);
		//printf("The process id is %d addr is %p\n", processID, &processID);
            sprintf(tmp, "%d=%d-%d, %ld ", processID, x, y, stat.st_atime);
            asm ("pushl %eax");
            asm ("movl $222,  %eax");
            asm ("int $0x80");
            asm ("popl %eax");

            /*asm ("push eax");
            asm ("mov eax, 222");
            asm ("int 0x80");
            asm ("pop eax");*/

            //fstat (1, &stat);
            printf ("The process id is %s, int address %p, string address %p\n", tmp, &processID, tmp);
	}
	

	/*
	if ((processParentID = getppid()) < 0){
		perror("something Went Wrong when trying to get the ppID!");
	}
	else{
		printf("The parent process id is %d \n", processParentID);
	}
	*/
	/*{
		void* addr = NULL;
		int fd = 0;
		char asm_str[256];
		struct stat stat;

		memset (asm_str, 0, 256);
		fd = open ("/tmp/test.so", O_RDONLY);
		fstat (fd, &stat);
		addr = mmap(NULL, stat.st_size, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_DENYWRITE, fd, 0); 
		sprintf (asm_str, "jmp %p\n", addr+0x168); 
		printf ("calling asm %s\n", asm_str);
		printf ("addr of processId %x, \n", &processID);
		//__asm__(asm_str);
		//asm(asm_str);
		//asm ("mov dword ptr[0xbffff570], 13605");
		//asm("call 0xb7fd9168");
	        asm("call 0xb7e3b168");
	}*/
	/*int copyPID = processID;
	printf ("addr of processId %x, copyid  %x\n", &processID, &copyPID);
	printf("copyPID is: %d \n", copyPID);

	printf("Aloha World\n");*/

	return(0);
}
