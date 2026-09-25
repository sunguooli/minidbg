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
typedef struct{
  unsigned long addr;
  long save;
  int is_temp;
  int active;
}bp_t;//断点结构
#define BP_MAX 16
typedef struct{
  bp_t items[BP_MAX];
  int count;
}bp_table_t;//断点数组用于整合断点
int  bp_find(bp_table_t *b,unsigned long addr){
  for(int i=0;i<BP_MAX;i++){
     if(b->items[i].addr==addr&& b->items[i].active){
      return i;
     }
  }
  return -1;

}
void bp_add(bp_table_t *b,unsigned long addr,long save){
  if(b->count>=BP_MAX){
    perror("b表已满！或已有addr存在\n");
    exit(1);
  }
  /* 改动1:先写入 items[count],再 count++。原来反了,第一个断点会写到 items[1],items[0] 是垃圾 */
  b->items[b->count].save=save;
  b->items[b->count].addr=addr;
  b->items[b->count].active=1;
  b->items[b->count].is_temp=0;
  b->count++;
}
void bp_remove(bp_table_t*b,unsigned long addr){
  int index;
  index=bp_find(b,addr);
  /* 改动2:if(index>=0)。原来 if(index) 把下标0当成没找到;
   * 且成功后要 return,原来 perror+exit 在 if 外面,撞断点就自杀 */
  if(index>=0){
    b->items[index].active=0;
    return;
  }
  perror("不存在||未知错误");
  exit(1);
}//至此 断点机构成功实现，下面是对于断点的重构！
//我们想重构断点结构的话，就需要相应的添加上增删查

/* 改动3:命令表 —— 名字映射处理函数,handler 返回 1 表示退出调试循环 */
typedef struct{
  const char *name;
  int (*handler)(pid_t pid);
}cmd_t;

int cmd_s(pid_t pid){ ptrace(PTRACE_SINGLESTEP, pid, 0, 0); return 0; }
int cmd_x(pid_t pid){ ptrace(PTRACE_CONT, pid, 0, 0); return 0; }
int cmd_q(pid_t pid){
  int exit_sig;
  printf("is exit? 1=yes\n");
  if (scanf("%d", &exit_sig) == 1 && exit_sig == 1) {
    ptrace(PTRACE_KILL, pid, 0, 0);
    return 1;
  }
  return 0;
}
int cmd_n(pid_t pid){ // TODO 步过留给你:首字节0xE8=call → rip+5下一次性断点 → CONT;否则退回单步
  (void)pid;
  printf("n 还没实现\n"); /* 原来是 return 0,输 n 整个程序直接退出,顺手修了 */
  return 0;
}

static const cmd_t CMDS[] = {
  {"s", cmd_s},
  {"x", cmd_x},
  {"q", cmd_q},
  {"n", cmd_n},
};

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
    char buf[32];
    bp_table_t p;       //用于交互调试
    memset(&p, 0, sizeof p); // 改动4:原来只清零 count,items 是栈垃圾,bp_find 可能误命中
    while (1) {
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
          bp_add(&p,addr,old);
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
          bp_remove(&p,addr);
          }else{
          ptrace(PTRACE_GETREGS,pid,0,&regs);
          printf("前面第三次else的rip:%llx\n",regs.rip);
          } 
         // =====================================================这上面的这段就是处理main开头的软断点的====================================               
            // ptrace(
          printf("(minidbg) ");
          if(scanf("%31s",buf)==-1){printf("buf赋值失败！");break;}
          /* 改动3配套:查表分发,替换原来的 if/else 链 */
          int found = 0, quit = 0;
          for(size_t i = 0; i < sizeof(CMDS)/sizeof(CMDS[0]); i++){
            if(strcmp(buf, CMDS[i].name) == 0){
              found = 1;
              quit = CMDS[i].handler(pid);
              break;
            }
          }
          if(!found) printf("unkown :%s\n",buf);
          if(quit) break;
    }
   }
  return 0;
  }
}
