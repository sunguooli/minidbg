#include<stdio.h>
#include<unistd.h>//fork ,exec
#include<sys/wait.h>//waitpid
#include<sys/ptrace.h>// ptrace
#include<stdlib.h>
#include<sys/types.h>// pid_t
int main(void){
	printf("lai kan yi xia shu chu ji ci\n");
    pid_t pid=fork();
    if(pid==0){
        ptrace(PTRACE_TRACEME,0,0,0);
        execl("./main.c","main.c",NULL);
        perror("execl");
        exit(1);
        printf("wo shi er zi\n");
        }else{
        int status;
        
        printf("wo shi ba ba\n");
        }
    return 0;

    }


