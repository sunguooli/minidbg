#include<stdio.h>
#include<unistd.h>//fork ,exec
#include<sys/wait.h>//waitpid
#include<sys/ptrace.h>// ptrace
#include<stdlib.h>//perror
#include<sys/types.h>// pid_t
#include<sys/user.h>
#include<errno.h>
struct user_regs_struct regs;
int get_exe_path(int pid,char*out,size_t outline){
    char link[64];
    snprintf(link,sizeof(link),"/proc/%d/exe",pid);
    ssize_t n=readlink(link,out,outline-1);
    if(n<=0){return -1;}
    else{out[n]=0;}
    return 0;
}
int main(void){
	printf("lai kan yi xia shu chu ji ci\n");
    pid_t pid=fork();
    if(pid==0){
        ptrace(PTRACE_TRACEME,0,0,0);
        printf("wo shi er zi\n");
        execl("./testprogram","testprogram",NULL);
        perror("execl");
        exit(1);
        }else{
        long addr=0x401126;
        printf("wo shi fu jin cheng\n");
        int status;
      while(1){
      int exit_sig;
       pid_t w= waitpid(pid,&status,0);
       if(w==-1){
       perror("waitpid");
       exit(1);
       }
        if(WIFSTOPPED(status)){
        printf("stopped by %d\n",WSTOPSIG(status));
        // ran hou zhe bian shi wo men dui yu cheng xu di zhi de ji sua
        
        long old=ptrace(PTRACE_PEEKTEXT,pid,(void*)addr,0);
        ptrace(PTRACE_POKETEXT,pid,(void*)addr,(old & ~0xffL)|0xcc);
        ptrace(PTRACE_GETREGS,pid,0,&regs);
        printf("rip=%llx\n",regs.rip);
        ptrace(PTRACE_CONT,pid,0,0);
        printf("is exit?,1=yes\n");
        if(scanf("%d",&exit_sig)==1&&exit_sig==1){
        ptrace(PTRACE_KILL,pid,0,0);
        break;
        }
        }else if(WIFEXITED(status)){
        printf("the exit status:%d\n",WEXITSTATUS(status));
        break;
        }else if(WIFSIGNALED(status)){
        printf("the kill-sig :%d\n",WTERMSIG(status)); 
        break; 
        }else{
        }
       }
      }
    return 0;

    }


