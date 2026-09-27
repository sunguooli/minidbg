#include<string.h>//用于strcmp的😄
#include <error.h>
#include <errno.h>      //改动11配套:errno,bt 爬链时判断 PEEK 失败用
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

/* 改动8:断点表提升为全局(原来是main里的局部变量)。
 * 原因:n步过/f步出的 handler 也要装断点,但 handler 签名只有 pid,
 * 够不到 main 的局部变量——和 regs 全局化是同一个理由 */
bp_table_t p;

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

/* 改动9:断点安装胶水 —— PEEK保存原字节 → POKE埋0xCC → 入表。
 * is_temp=1 表示一次性断点(命中即删),给 n步过/f步出 用;0=普通断点 */
void bp_install(pid_t pid,bp_table_t *b,unsigned long addr,int is_temp){
  long save = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);
  ptrace(PTRACE_POKETEXT, pid, (void *)addr, (save & ~0xffL) | 0xcc);
  bp_add(b,addr,save);
  b->items[b->count-1].is_temp=is_temp;
}

/* 改动11:符号翻译胶水(作弊版) —— popen 调 nm 解析目标二进制的符号表。
 * bt 爬出来的是裸地址,靠它翻译成"函数名+0x偏移";查不到(如libc)就打 ???
 * 原理:nm -n 输出按地址排序的符号行 "地址 类型 名字",只收代码段符号(T/t/W) */
typedef struct{
  unsigned long addr;
  char name[64];
}sym_t;
#define SYM_MAX 4096
sym_t SYMS[SYM_MAX];
int sym_count = 0;

void sym_load(const char *path){
  char cmd[300];
  snprintf(cmd, sizeof cmd, "nm --defined-only -n %s 2>/dev/null", path);
  FILE *fp = popen(cmd, "r");
  if(!fp){ perror("popen nm"); return; }
  char line[256];
  while(fgets(line, sizeof line, fp) && sym_count < SYM_MAX){
    unsigned long a; char t; char name[64];
    if(sscanf(line, "%lx %c %63s", &a, &t, name) == 3 && (t=='T'||t=='t'||t=='W')){
      SYMS[sym_count].addr = a;
      strncpy(SYMS[sym_count].name, name, 63);
      SYMS[sym_count].name[63] = 0;
      sym_count++;
    }
  }
  pclose(fp);
}

/* 查"最后一个 <= addr 的符号" = addr 落在哪个函数里。SYMS 已按地址升序 */
void sym_print(unsigned long addr){
  int best = -1;
  for(int i = 0; i < sym_count; i++){
    if(SYMS[i].addr <= addr) best = i; else break;
  }
  if(best < 0){ printf("???"); return; }
  unsigned long off = addr - SYMS[best].addr;
  if(off) printf("%s+0x%lx\n", SYMS[best].name, off);
  else    printf("%s\n", SYMS[best].name);
}

/* 改动3:命令表 —— 名字映射处理函数
 * handler 返回值约定: 0=已放行子进程,回waitpid; 1=退出调试; 2=没放行,留在prompt继续问 */
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
  return 2; /* 改动5:取消退出=没放行子进程,按约定返回2继续问。原来return 0会被当成"已放行",回waitpid死锁 */
}
int cmd_n(pid_t pid){ /*
   * 1.GETREGS 拿 rip(regs 是全局,直接用)
   * 2.PEEKTEXT 读 rip 处首字节,& 0xff 取低字节
   * 3.== 0xE8 → bp_install(pid,&p,rip+5,1) 下一次性断点 → CONT → return 0
   * 4.否则退回 SINGLESTEP → return 0
   * 命中恢复(还原字节/rip回退/删表项)在主循环 else 分支的改动10 里,不用你管 */
  ptrace(PTRACE_GETREGS,pid,0,&regs);
  long n_old=ptrace(PTRACE_PEEKTEXT,pid,(void*)regs.rip,0);
  if((n_old & 0xff)==0xe8){
      printf("进入call\n");
      bp_install(pid,&p,regs.rip+5,1);
      ptrace(PTRACE_CONT,pid,0,0);
      return 0;
     }else{
     printf("步过退化..\n");
     ptrace(PTRACE_SINGLESTEP,pid,0,0);
     return 0;
     }
  return 2; /* 改动6:占位命令没有放行子进程,按新约定返回2。原来的0在旧结构下同样死锁 */
}

int cmd_f(pid_t pid){
    ptrace(PTRACE_GETREGS,pid,0,&regs);
    long f_old=ptrace(PTRACE_PEEKTEXT,pid,(void*)(regs.rbp+8),0);
    bp_install(pid,&p,f_old,1);//此时f_old里面是rbp+8存的函数的返回地址
    ptrace(PTRACE_CONT,pid,0,0);
    return 0;
}

int cmd_bt(pid_t pid){ /* TODO 栈回溯核心留给你写(符号胶水已就绪):
   * 本质:把 cmd_f 里"读 rbp+8"的动作循环起来,顺着 rbp 链一帧帧往上爬
   *   GETREGS 拿当前 rbp
   *   while (rbp != 0 且 PEEK 没失败) {
   *     ret = PEEKTEXT(rbp + 8)     ← 这一帧的返回地址(和 cmd_f 同一个读法)
   *     打印 ret,并用 sym_print(ret) 翻译成"函数名+0x偏移"
   *     rbp = PEEKTEXT(rbp)         ← [rbp] 里存的是上一帧的 rbp,爬上去
   *   }
   * 终止条件(两个都要有,否则爬进虚空):
   *   rbp == 0      → 到 _start 了,链走完
   *   PEEK 失败     → 链断了。判断法:errno=0 再 PEEK,返回 -1 且 errno!=0 就是失败
   * 这是查询类命令:不放行子进程 → return 2 */
  errno=0;
  ptrace(PTRACE_GETREGS,pid,0,&regs);
  long walk=regs.rbp;
  printf("起始rbp:%lx\n",walk);
  while(walk){
      errno=0;
      long ret=ptrace(PTRACE_PEEKDATA,pid,(void*)(walk+8),0);
      if(ret==-1&&errno!=0){
      break;
       }
      printf("该次返回地址：%lx\n",ret);
      sym_print(ret);
      errno=0;
      walk=ptrace(PTRACE_PEEKDATA,pid,(void*)walk,0);
      if(walk==-1&&errno!=0){
      break;
      }
  }
  return 2;
}

static const cmd_t CMDS[] = {
  {"s", cmd_s},
  {"x", cmd_x},
  {"q", cmd_q},
  {"n", cmd_n},//实现步过
  {"f", cmd_f},//实现步出，就是在函数内部的调试里面直接跳出去，主要利用rbp读取返回值，提前读取而已
  {"bt", cmd_bt},//栈回溯:顺 rbp 链爬出整条调用链
};

int main(void) { // s是单步调试，x是放行，q是退出
  printf("lai kan yi xia shu chu ji ci\n");
  pid_t pid = fork(); // zai zhe bian fu zhi zi jin cheng
  if (pid == 0) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    printf("wo shi er zi\n");
    execl("./test_bt_nopie", "test_bt_nopie", NULL);
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
    memset(&p, 0, sizeof p); // 改动4:原来只清零 count,items 是栈垃圾,bp_find 可能误命中(改动8后 p 是全局,memset保留双保险)
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
          /* 改动12:首次停下时加载符号表 —— 复用现成的 get_exe_path 拿目标路径,
           * 交给 sym_load 调 nm 解析。只加载一次,所以放在 !pid_main 这个只跑一次的分支 */
          char exe_path[256];
          if(get_exe_path(pid, exe_path, sizeof exe_path) == 0) sym_load(exe_path);
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
          /* 改动10:通用断点命中处理 —— rip-1 查表,命中一次性断点就
           * 恢复字节、rip回退、删表项。n步过 CONT 后撞 temp 断点会走这里;
           * 普通单步查不到表项,照旧只打印 rip */
          int hit = bp_find(&p, regs.rip - 1);
          if(hit >= 0 && p.items[hit].is_temp){
            unsigned long bp_addr = p.items[hit].addr;
            ptrace(PTRACE_POKETEXT, pid, (void *)bp_addr, p.items[hit].save);
            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, pid, 0, &regs);
            printf("步过完成 rip=%llx\n",regs.rip);
            bp_remove(&p, bp_addr);
          }else{
            printf("前面第三次else的rip:%llx\n",regs.rip);
          }
          } 
         // =====================================================这上面的这段就是处理main开头的软断点的====================================               
            // ptrace(
          /* 改动7:prompt包进小循环。unknown/q取消/n占位这类"没放行子进程"的情况
           * quit=2 → continue 继续问;只有真正放行(0)或退出(1)才跳出小循环。
           * found 标志删除:用循环下标 i 是否走到末尾判断是否匹配 */
          int quit;
          while (1) {
            printf("(minidbg) ");
            if(scanf("%31s",buf)==-1){printf("buf赋值失败！");quit=1;break;}
            quit = 2;//先设个初始值因为 非调试杀死指令不会为quit赋值！
            size_t i;
            for(i = 0; i < sizeof(CMDS)/sizeof(CMDS[0]); i++){
              if(strcmp(buf, CMDS[i].name) == 0){
                quit = CMDS[i].handler(pid);
                break;
              }
            }
            if(i == sizeof(CMDS)/sizeof(CMDS[0])) {printf("unkown :%s\n",buf);}
            if(quit == 2) continue;//与if i配合完成对于 误触退出和输入错误 的2返回值处理
            break;
          }
          if(quit == 1) break;//配合上一步的break完成对于kill指令的父进程所有循环终止
    }
   }
  return 0;
  }
}
