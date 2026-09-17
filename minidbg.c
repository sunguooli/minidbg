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
        printf("wo shi er zi\n");
        execl("testprogram","testprogram.c",NULL);
        perror("execl");
        exit(1);
        }else{
        printf("wo shi fu jin cheng\n");
        int status;
       pid_t w= waitpid(pid,&status,0);
       if(w==-1){
       perror("waitpid");
       exit(1);
       }
        if(WIFSTOPPED(status)){
        printf("stopped by %d\n",WSTOPSIG(status));
        }else if(WIFEXITED(status)){
        printf("the exit status:%d\n",WEXITSTATUS(status));
        }else if(WIFSIGNALED(status)){
        printf("the kill-sig :%d\n",WTERMSIG(status));
         
        }
       }
       pause();
    return 0;

    }


