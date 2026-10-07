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
long p_flag=0;
int get_exe_path(int pid, char *out, size_t outline) {//拿文件真实路径 为了
  char link[64];  //这个是用来存路径名字的
  snprintf(link, sizeof(link), "/proc/%d/exe", pid);
  ssize_t n = readlink(link, out, outline - 1);
  if (n <= 0) {//n的返回值小于等于零 表示 读取失败
    return -1;
  } else {
    out[n] = 0;
  }
  return 0;
}

/* 改动18:读 /proc/pid/maps 拿目标程序的加载基址 —— PIE 支持的核心。
 * 原理:加载器把文件镜像整体抬到基址处,第一行映射到 exe_path 的记录,
 * 其起始地址就是基址。nopie 恒为 0x400000,PIE 每次运行随机(ASLR)。
 * 和 get_exe_path 的分工:exe 回答"跑的是哪个文件",maps 回答"文件被抬到哪" */
unsigned long get_load_base(int pid, const char *exe_path){//拿基址 模式就是 map存指令 然后fp存该进程的
  char maps[64];    //这个是存路径的，配合fopen
  snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
  FILE *fp = fopen(maps, "r");
  if(!fp){ perror("fopen maps"); return 0; }
  char line[512];// 用来存入不同运行基址 匹配的
  unsigned long base = 0;//存入基址
  while(fgets(line, sizeof line, fp)){
    if(strstr(line, exe_path)){   /* maps 每行末尾是路径,首次出现即最低映射=基址 */
      sscanf(line, "%lx", &base);
      break;
    }
  }
  fclose(fp);
  return base;
}

/* 改动18:基址修正量。所有跨世界换算的唯一参数:
 *   文件坐标 + g_base = 内存地址   (下断点,正方向)
 *   内存地址 - g_base = 文件坐标   (符号翻译,反方向)
 * nopie 下符号已是绝对地址,g_base 恒为 0 —— "nopie 就是基址为 0 的特例"在此落地 */
unsigned long g_base = 0;
typedef struct{
  unsigned long addr;
  long save;
  int is_temp;
  int active;
  int restored;/*永久断点已修复等待单步运行*/
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

/* 改动13:子进程内存访问统一入口 —— 收口原来散落九处的 PEEK/POKE。
 * 语义约定:addr 一律是内存绝对地址(运行时地址);符号地址(文件偏移)须换算后再传入,
 * PIE 阶段的基址换算将来挂在调用点与这里之间,调用方零改动。
 * 注:Linux 上 PEEKTEXT 与 PEEKDATA 完全等价,bt 读栈也走 mem_peek */
long mem_peek(pid_t pid, unsigned long addr){
  return ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);
}
void mem_poke(pid_t pid, unsigned long addr, long val){
  ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)val);
}

int  bp_find(bp_table_t *b,unsigned long addr){
  for(int i=0;i<BP_MAX;i++){
     if(b->items[i].addr==addr&& b->items[i].active){
      return i;
     }
  }
  return -1;

}
void bp_add(bp_table_t *b,unsigned long addr,long save,int is_temp,int restored){

  if(b->count>=BP_MAX){
    perror("b表已满！或已有addr存在\n");
    exit(1);
  }
  /* 改动1:先写入 items[count],再 count++。原来反了,第一个断点会写到 items[1],items[0] 是垃圾 */
  b->items[b->count].save=save;
  b->items[b->count].addr=addr;
  b->items[b->count].active=1;
  b->items[b->count].is_temp=is_temp;
  b->items[b->count].restored=restored;
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
  long save = mem_peek(pid, addr);           /* 改动13:走统一入口 */
  mem_poke(pid, addr, (save & ~0xffL) | 0xcc);
  int restored=1;
  if(is_temp){restored=0;}
  bp_add(b,addr,save,is_temp,restored);
}

/* 改动14:命中检查+恢复,收口进断点模块。
 * 原来这段散在主循环 else 分支,直接摸 p.items[] 内部字段——断点的一生
 * (埋→命中→恢复→删)现在完整住在模块内。
 * 约定:调用前调用方已完成 GETREGS(全局 regs 是最新的)。
 * 命中临时断点:恢复原字节、regs.rip 回退并 SETREGS、删表项,返回 1;
 * 未命中(普通单步停下):返回 0。命中路径会更新全局 regs.rip,调用方直接打印即可 */
int bp_handle_hit(pid_t pid, bp_table_t *b){
  int hit = bp_find(b, regs.rip - 1);
  if(hit >= 0 && b->items[hit].is_temp){/*此处针对临时断点，暂未考虑永久断点*/
    unsigned long bp_addr = b->items[hit].addr;
    mem_poke(pid, bp_addr, b->items[hit].save);   /* 改动13:走统一入口 */
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
    bp_remove(b, bp_addr);
    return 1;
  }/*考虑直接*/
  return 0;
}

/* 改动15:恢复原字节+删表项,给首次 main 断点命中用。
 * 原来主循环靠局部变量 old 存原字节 POKE 回去;bp_install 已经把原字节
 * 存进表里(save 字段),old 变量随之废弃 */
void bp_restore(pid_t pid, bp_table_t *b, unsigned long addr){
  int idx = bp_find(b, addr);
  if(idx < 0){ perror("bp_restore: 表中没有该断点"); exit(1); }
  mem_poke(pid, addr, b->items[idx].save);
  bp_remove(b, addr);
}
void bp_prestored(pid_t pid, bp_table_t *b, unsigned long addr){//单独处理永久断点避免 删表项
  int idx=bp_find(b,addr);
  if(idx<0){perror("未找到该永久断点");}
  p.items[p.count].restored=0;
  return;
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

void sym_load(const char *path){//将管道里面的内容填入进入表里面 用来配合栈回溯
  char cmd[300];
  snprintf(cmd, sizeof cmd, "nm --defined-only -n %s 2>/dev/null", path);
  FILE *fp = popen(cmd, "r");
  if(!fp){ perror("popen nm"); return; }
  char line[256];
  while(fgets(line, sizeof line, fp) && sym_count < SYM_MAX){
    unsigned long a; char t; char name[64];
    /* 改动11修正:W(weak)去掉——weak 可能是数据符号(如 data_start),混进来会坐表尾污染查询 */
    if(sscanf(line, "%lx %c %63s", &a, &t, name) == 3 && (t=='T'||t=='t')){
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
  /* 改动11修正:命中表尾且偏移非0 → 目标在所有符号覆盖范围之外(如libc),
   * 表尾符号的"身体"多大没人知道,不能瞎算偏移,打 ??? */
  if(best == sym_count-1 && off != 0){ printf("???\n"); return; }
  if(off) printf("%s+0x%lx\n", SYMS[best].name, off);
  else    printf("%s\n", SYMS[best].name);
}

/* 改动17:按名字查符号地址 —— 拆掉"硬编码 0x401154"的拐杖。
 * 返回值是文件坐标(nopie=绝对地址,PIE=偏移),调用方负责 +g_base 换算。
 * 没找到返回 0(SYMS 里不存在地址为 0 的合法符号,0 可安全当"未找到") */
unsigned long sym_find(const char *name){
  for(int i = 0; i < sym_count; i++){
    if(strcmp(SYMS[i].name, name) == 0) return SYMS[i].addr;
  }
  return 0;
}

/* 改动3:命令表 —— 名字映射处理函数
 * handler 返回值约定: 0=已放行子进程,回waitpid; 1=退出调试; 2=没放行,留在prompt继续问 */
typedef struct{
  const char *name;
  int (*handler)(pid_t pid);
}cmd_t;

int cmd_s(pid_t pid){ ptrace(PTRACE_SINGLESTEP, pid, 0, 0); return 0; }
int cmd_x(pid_t pid){ 
  int q=0;
  q=bp_find(&p,regs.rip);
  if(q>=0&&p.items[q].restored){//判断是不是恢复后的断点，然后再判断下一步是不是
    p_flag=regs.rip;// 遇到我们的永久断点处理后改变标记位
    ptrace(PTRACE_SINGLESTEP,pid,0,0);
  }
  ptrace(PTRACE_CONT,pid,0,0);
  return 0; }
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
   * 命中恢复(还原字节/rip回退/删表项)在主循环 else 分支的 bp_handle_hit(改动14) 里,不用你管 */
  ptrace(PTRACE_GETREGS,pid,0,&regs);
  long n_old=mem_peek(pid, regs.rip);        /* 改动13:走统一入口。rip 是运行时地址,不换算 */
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
    long f_old=mem_peek(pid, regs.rbp+8);    /* 改动13:走统一入口。rbp 是运行时地址,不换算 */
    bp_install(pid,&p,f_old,1);//此时f_old里面是rbp+8存的函数的返回地址
    ptrace(PTRACE_CONT,pid,0,0);
    return 0;
}

int cmd_bt(pid_t pid){ /* 栈回溯核心留给你写(符号胶水已就绪):
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
      long ret=mem_peek(pid, walk+8);        /* 改动13:走统一入口(原 PEEKDATA,Linux 下等价) */
      if(ret==-1&&errno!=0){
      break;
       }
      printf("该次返回地址：%lx\n",ret);
      /* 改动18:内存绝对地址 -g_base → 文件坐标再查表(跨世界反方向)。
       * g_base=0(nopie)时与旧行为逐字节一致;libc 地址减完仍在表外,表尾守卫照旧打 ??? */
      sym_print(ret - g_base);
      errno=0;
      walk=mem_peek(pid, walk);              /* 改动13:走统一入口(原 PEEKDATA,Linux 下等价) */
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

int main(int argc, char **argv) { // s是单步调试，x是放行，q是退出
  /* 改动16:目标程序从命令行指定 —— 拆掉 execl 硬编码拐杖。
   * 用法:./minidbg <目标程序>  (目标自身的命令行参数暂不支持) */
  if(argc < 2){ fprintf(stderr, "用法: %s <目标程序>\n", argv[0]); return 1; }
  printf("lai kan yi xia shu chu ji ci\n");
  pid_t pid = fork(); // zai zhe bian fu zhi zi jin cheng
  if (pid == 0) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    printf("wo shi er zi\n");
    execl(argv[1], argv[1], NULL);   /* 改动16:原写死 "./test_bt_nopie" */
    perror("execl");
    exit(1);
  } else {
    unsigned long addr = 0;   /* 改动17:不再硬编码,首次停下时由 sym_find("main")+g_base 填入 */
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
        if(p_flag){//  重埋永久断点   重埋分支
          ptrace(PTRACE_GETREGS,pid,0,&regs);
          int idx=bp_find(&p,p_flag);
          mem_poke(pid,p_flag,(p.items[idx].save & ~0xff)|0xcc);
          bp_prestored(pid,&p,p_flag);
          p_flag=0;
          ptrace(PTRACE_CONT,pid,0,0);
          continue;
        }
        if (!pid_main) { //  这一步有两个原因，其中一个是防止重复读取old导致字节码污染，然后就是在这边用上我们的pid_main用来标记并写入oxcc
                         //  的，然后放行撞上断点
          /* 改动17+18:入口断点地址不再硬编码 —— 先 sym_load 填符号表,再 sym_find("main")
           * 拿文件坐标,最后 +g_base 换算成内存地址。顺序必须如此(sym_find 依赖符号表),
           * 所以原来"先 bp_install 后 sym_load"的顺序对调了 */
          char exe_path[256];
          if(get_exe_path(pid, exe_path, sizeof exe_path) == 0){
            sym_load(exe_path);
            /* 基址修正判定:m(文件坐标) 比 maps 基址还小 → 它是偏移(PIE),g_base=基址;
             * 否则符号已是绝对地址(nopie),g_base 保持 0 不动 */
            unsigned long m = sym_find("main");
            unsigned long mb = get_load_base(pid, exe_path);
            if(m != 0 && m < mb) g_base = mb;
            addr = m + g_base;
          }
          if(addr == 0){
            fprintf(stderr, "找不到 main 符号(目标被 strip 了?),本次不下入口断点\n");
            done = 1;   /* 没埋雷就没人需要排雷,防止 !done 分支对空表 bp_restore */
          }else{
            bp_install(pid, &p, addr, 0);   /* 改动15:埋断点全项目只有这一个入口 */
          }
          pid_main = 1;
          ptrace(PTRACE_CONT, pid, 0, 0);
          continue;
        } else if(!done){
          ptrace(PTRACE_GETREGS, pid, 0, &regs);
          regs.rip -= 1;

          printf("这是done的rip=%llx\n", regs.rip);
          ptrace(PTRACE_SETREGS, pid, 0, &regs);
          /* 改动15:原字节从断点表 save 字段恢复(原 POKE old),old 变量废弃 */
          bp_restore(pid, &p, addr);
          done=1;
          }else{
          ptrace(PTRACE_GETREGS,pid,0,&regs);
          /* 改动14:命中检查+恢复收口进 bp_handle_hit。原来这里直接摸 p.items[] 内部字段;
           * 命中时 regs.rip 已被函数内回退,下面两种打印和原行为逐字节一致 */
          if(bp_handle_hit(pid, &p)){
            printf("步过完成 rip=%llx\n",regs.rip);
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
