#include<string.h>//用于strcmp的😄
#include <error.h>
#include <stdio.h>
#include <stdlib.h>     //perror
#include <sys/ptrace.h> // ptrace
#include <sys/types.h>  // pid_t
#include <sys/user.h>
#include <sys/wait.h> //waitpid
#include <unistd.h>   //fork ,exec
struct user_regs_struct regs;
int get_exe_path(int pid, char *out, size_t outline) {
  char link[64]; 
  snprintf(link, sizeof(link), "/proc/%d/exe", pid);
  ssize_t n = readlink(link, out, outline - 1);
  if (n <= 0) {
    return -1;
  } else {
    out[n] = 0;
  }
  return 0;
}
int main(void) { // s是单步调试，x是放行，q是退出
  printf("lai kan yi xia shu chu ji ci\n");
  pid_t pid = fork(); // zai zhe bian fu zhi zi jin cheng
  if (pid == 0) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    printf("wo shi er zi\n");
    execl("./testprogram_nopie", "testprogram_nopie", NULL);
    perror("execl");
    exit(1);
  } else {
    long addr = 0x401136;
    long old;
    int done = 0;
    int pid_main = 0;
    printf("wo shi fu jin cheng\n");
    int status;
    char buf[32];       //用于交互调试
    while (1) {
      int exit_sig;
      pid_t w = waitpid(pid, &status, 0);
      if(WIFEXITED(status)){printf("退出状态为：%d\n",WEXITSTATUS(status));break;}
      else if(WIFSIGNALED(status)){printf("被杀死的信号为：%d\n",WTERMSIG(status));break;}
      if (w == -1) {
        perror("waitpid");
        exit(1);
      }
      if (WIFSTOPPED(status)) {
        printf("stopped by %d\n", WSTOPSIG(status));
        // ran hou zhe bian shi wo men dui yu cheng xu di zhi de ji sua
        if (!pid_main) { //  这一步有两个原因，其中一个是防止重复读取old导致字节码污染，然后就是在这边用上我们的pid_main用来标记并写入oxcc
                         //  的，然后放行撞上断点
          old = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);
          ptrace(PTRACE_POKETEXT, pid, (void *)addr, (old & ~0xffL) | 0xcc);
          ptrace(PTRACE_GETREGS, pid, 0, &regs);
         // printf("刚下断点时的rip=%llx\n",regs.rip); // 这一步我觉得用处不是很大
          // ,与下面的查看rg产生误导性
          pid_main = 1;
          ptrace(PTRACE_CONT, pid, 0, 0);
          continue;
        } else if(!done){
          ptrace(PTRACE_GETREGS, pid, 0, &regs);
          regs.rip -= 1;

          printf("这是done的rip=%llx\n", regs.rip);
          ptrace(PTRACE_SETREGS, pid, 0, &regs);
          ptrace(PTRACE_POKETEXT, pid, (void *)addr, old);
          done=1;
          }else{
          ptrace(PTRACE_GETREGS,pid,0,&regs);
          printf("前面第三次else的rip:%llx\n",regs.rip);
          }       
         // =====================================================这上面的这段就是处理main开头的软断点的====================================               
            // ptrace(
          printf("(minidbg) ");
          if(scanf("%31s",buf)==-1){printf("buf赋值失败！");break;}
          if(strcmp(buf,"s")==0){
            ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
            // yao jie jue duan dian hui tian de  wen ti!!
           // waitpid(
            //    pid, &status,
             //   0); // singlestep是异步的,没有waitpid的话，那么就可能因为循环导致报错
             
           
            // 我们可以在这一步做很多事情，比如观察什么的
           }else if(strcmp(buf,"q")==0){
                   printf("is exit? 1=yes\n");
                   if (scanf("%d", &exit_sig) == 1 && exit_sig == 1) {
                   ptrace(PTRACE_KILL, pid, 0, 0);//zhe yi bu ke yi bao liu 
                   break;
                  }
          }else if(strcmp(buf,"x")==0){
                   ptrace(PTRACE_CONT,pid,0,0);  //这些判断语句可以放在上层while 下面 
                     
           }else{
          printf("unknow :%s",buf);
     }
    }
   }
    
  return 0;
  }
}
