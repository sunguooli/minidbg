# minidbg

一个用 C + ptrace 从零实现的迷你调试器（x86-64 Linux）。学习项目：目标是**吃透调试器的底层机制**，不是堆功能。所有机制的推导、踩坑和设计决策记录在 [NOTES.md](NOTES.md)。

## 功能

- [x] fork + TRACEME + exec 启动并追踪子进程
- [x] 软件断点完整生命周期：int3 埋点 → 命中 → 恢复原字节 → 单步抬过 → 重埋（永久断点 gdb 同款流程）
- [x] 断点命令：`b <函数名>` / `b *<地址>` 下断点，`info` 列表，`d <编号>` 删除（含防重复安装）
- [x] 单步 `s` / 继续 `x` / 步过 `n`（识别 call rel32，rip+5 一次性断点）/ 步出 `f`（读 [rbp+8] 返回地址）
- [x] 栈回溯 `bt`：顺 rbp 链爬调用栈，符号翻译成 `函数名+0x偏移`
- [x] 符号解析：popen 调 nm 读 .symtab，升序表 + 区间定位
- [x] **PIE 支持**：读 /proc/pid/maps 拿随机基址，文件偏移 ⟷ 内存地址双向换算，nopie/PIE 通吃
- [x] 命令表驱动的 REPL（表驱动分发，handler 返回值三态约定）
- [ ] strip 对抗：无符号时读 ELF 头 e_entry 下入口断点（进行中）
- [ ] 反调试 与绕过（计划中）
- [ ] 接入 agent 实现自动化二进制分析（远期）

## 架构

```
main 状态机(waitpid 驱动)
  ├─ 初始化停  → 加载符号 + 算基址 + 下 main 断点
  ├─ 中转停    → 永久断点重埋(p_flag 接力,对用户隐身)
  └─ 通用停    → bp_handle_hit 三态分发 → prompt 命令循环

四个底层模块:
  mem_peek/mem_poke   子进程内存访问唯一入口(绝对地址语义)
  bp_*                断点的一生全在模块内(埋→命中→恢复→重埋→删)
  sym_*               文件世界翻译官(SYMS 表全是文件坐标)
  g_base              两个世界的桥:nopie 恒 0,PIE 读 maps
```

## 编译与运行

```bash
gcc -Wall -o minidbg minidbg.c

# 目标程序建议:-g -O0 -fno-omit-frame-pointer(PIE/nopie 均可)
gcc -g -O0 -fno-omit-frame-pointer test_bt.c -o test_bt

./minidbg ./test_bt
```

命令一览：

| 命令 | 作用 |
|---|---|
| `s` | 单步一条指令 |
| `x` | 继续运行 |
| `n` | 步过（call 不进函数体） |
| `f` | 步出（跑完当前函数） |
| `bt` | 栈回溯 + 符号翻译 |
| `b main` / `b *0x40115b` | 下永久断点（按名/按绝对地址） |
| `info` | 断点列表 |
| `d <编号>` | 删断点 |
| `q` | 退出（有二次确认） |

## 环境

- Linux x86-64（开发于 Kali）
- gcc、nm（符号解析依赖 binutils）
