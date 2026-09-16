# minidbg

一个用 C 和 ptrace 写的简易调试器（学习项目）。

## 目标功能
- [ ] fork + execve 启动并 attach 子进程
- [ ] 读写寄存器与内存
- [ ] 软件断点（0xCC / int3）
- [ ] 单步执行
- [ ] continue + 简单命令行
- [ ] 用自写调试器对抗常见反调试手法（后续文章素材）

## 环境
- Kali Linux (x86-64)
- gcc, make

## 编译与运行
```bash
make            # 编译
./minidbg ./test_program    # 调试测试程序
