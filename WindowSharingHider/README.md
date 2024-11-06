您提供的代码确实展示了内存注入（Memory Injection）的一个典型方案，它的目的是通过直接在目标进程的内存中注入并执行自定义的代码，从而修改或操控目标进程的行为。内存注入是进程间通信（IPC）和反向工程领域中的一种常见技术。

这个过程的核心步骤通常包括：
1. 打开目标进程

使用 OpenProcess 函数打开目标进程并获得其句柄。这个句柄允许你在目标进程的上下文中执行各种操作（例如读取、写入内存，创建线程等）。

var procHandle = OpenProcess(0x38, true, procId);

2. 获取进程的模块信息

通过 EnumProcessModulesEx 或 GetModuleFileNameEx 等 API 获取目标进程加载的模块（DLL）的信息。在这种情况下，我们的目标是查找 user32.dll，因为它包含了 SetWindowDisplayAffinity 这样能控制窗口显示亲和性的函数。

EnumProcessModulesEx(procHandle, ptrs, 0, out UInt32 bytesNeeded, 3);

3. 查找函数地址

通过读取目标进程的导出表、解析函数名及其地址，这段代码使用了较为复杂的机制来获取 SetWindowDisplayAffinity 函数的内存地址。它首先遍历目标进程的模块，定位 user32.dll，然后通过 ReadProcessMemory 等 API 读取导出表，最终获得函数地址。

var SetWindowDisplayAffinityAddr = 0ul;

4. 构造和注入汇编代码

一旦获得了目标函数的地址，代码通过汇编语言构建了一段自定义的机器代码，将 SetWindowDisplayAffinity 函数的调用嵌入到目标进程的内存中。使用 WriteProcessMemory 将构建好的汇编代码写入目标进程的内存中。

asm.Add(0x68); // push
asm.AddRange(BitConverter.GetBytes((UInt32)dwAffinity)); // 参数推入栈

这部分的代码构建了一些汇编指令，包括 push、mov 和 call，这些指令用于执行函数调用。
5. 创建远程线程

接下来，代码使用 CreateRemoteThread 在目标进程中创建一个新的线程来执行注入的汇编代码。通过 WaitForSingleObject 等 API 等待远程线程执行完成。

var thread = CreateRemoteThread(procHandle, IntPtr.Zero, 0, codePtr, IntPtr.Zero, 0, IntPtr.Zero);

6. 清理和释放资源

注入代码执行完毕后，使用 VirtualFreeEx 和 CloseHandle 等 API 释放分配的内存资源，确保进程的资源得以清理。

VirtualFreeEx(procHandle, codePtr, 0, 0x8000);
CloseHandle(procHandle);

内存注入的典型应用

内存注入是一种非常强大但也非常危险的技术，通常用于以下场景：

    进程操控：允许开发者在目标进程中注入代码，改变进程行为。例如，可以修改目标进程的逻辑，或者实现特定功能（如劫持函数调用、修改窗口属性等）。

    反向工程：很多反向工程工具使用内存注入技术来分析程序行为，绕过反调试机制，或者破坏软件的保护措施。

    作弊和破解：在一些游戏或软件中，作弊者通过注入代码来修改程序的内存数据，从而获得不正当的优势或破解软件。

    调试和安全研究：内存注入也可以用于调试或测试程序的安全性。例如，某些安全研究人员通过注入代码来测试目标进程的防护机制。

技术挑战与风险

内存注入技术存在很多挑战和风险，包括：

    安全性：内存注入可以被恶意软件用于攻击目标系统，因此系统防御机制（如反病毒软件、Windows Defender）通常会对这种行为进行检测和拦截。

    兼容性：不同版本的 Windows 操作系统对内存访问和远程线程的操作有所不同，需要特别小心适配不同平台的实现。

    稳定性：不当的内存写入可能导致目标进程崩溃或异常行为，可能会导致数据丢失或系统崩溃。

    合法性：在某些情况下，内存注入可能会违反软件的使用条款，甚至触犯法律，特别是当它被用于破解、修改或非法操控软件时。

总的来说，内存注入是一个非常强大的技术，通常用于一些底层操作和特定需求。对于有相关需求的开发者来说，它提供了许多灵活性，但同时也带来了诸多挑战和风险。