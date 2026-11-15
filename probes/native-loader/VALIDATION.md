# 2026-11-15：四个原始程序的 Loader 集成验证

后续同日更新：用户补充 Wolf 实机也会重启；新模拟器默认保存故障现场后重建 HLE OS。
本文件保留前次验证记录，最新结果见 [模拟器验证](../emulator/VALIDATION-2026-11-15.json)，
KhiCAS 具体卡点、12 KiB 影子页推导及下一条路线见 [专项说明](KHICAS-BLOCKERS.md)。

结论：原生 RAM Loader 链路已实现，**四个程序没有全部跑通**。
三个小程序经真实 Bfile 读取与校验后进入游戏，Minesweeper 完成菜单替换、
恢复、释放以及重新加载。KhiCAS 的文件映射后端仍未实现。结果全部来自
功能级模拟器；此前的小型实机 Probe 不能替代本轮四个程序的实机验收。

| 样本 | 原文件字节 | 通过 Loader 的观察 | 退出与限制 |
| --- | ---: | --- | --- |
| KhiCAS | 2,094,444 | 加载前拒绝：`Need file mapping` | 512 个 4 KiB 页，超过 160 KiB RAM 后端限制；未执行目标 |
| Wolfenstein | 98,708 | 标题、进入 Level 1、移动与转向 | Quit 跳转 `A0000000`，原 G1A 直接运行也如此；未完成退出闭环 |
| Fruit Ninja | 66,236 | 连续键盘滑动后进入游戏、切水果 | 菜单替换触发旧 SDK 退出函数，停在未知 `0x01E7`；直接运行同样失败 |
| Minesweeper 1.0.13 | 126,448 | 操作卡、开始、开格、移动、插旗、暂停与恢复、保存 | MENU 替换触发清理，映射检查为 0；保留存档重开 Loader 后可再次运行与退出 |

KhiCAS 直接运行基线使用其隔离内存配置，能算出 `2+2=4`；那不是 Loader 的
成功结果。小程序对照与 Loader 均使用模拟器默认 192 KiB OS 堆。以 48 KiB
预算装载 Fruit 时按预期拒绝，说明本轮不能把默认模拟器成功直接推广到实机。

## 身份与产物

所有 BIN 都是对应原 G1A 的原字节副本，只改名称与后缀。Minesweeper 用的是
用户指定的 `advanced-minesweeper/dist/Minesweeper.g1a`，没有换成旧 AMINE 样本。

| 样本 | SHA-256 | 替换的 syscall gateway 常量池数 |
| --- | --- | ---: |
| KhiCAS | `4a9d1c18009d987dc7c8745b7fc099b3c6e8006ebbb2ee5e4b483934be757473` | 51 |
| Wolf | `d8c8b567b7a2f108e4969ca0f3461a9e82d9669c834f26f7f476f1b5eebf88ca` | 38 |
| Fruit | `5c5bd8f2c42add4feb9eb4112f134d00c45066eb80be805c3f872b27f451eaf6` | 46 |
| Minesweeper | `0cf3f1fa10c818cf5126d0555c2828151283989457c7da8844a422aeb21d8284` | 2 |

Release `Loader.g1a`：13,508 字节，SHA-256
`8845cf40957378bb4cb698e5d7839ca104d1b37498ae48ac90d037fa18f41646`。
匹配 ELF：`0429dfac1dfea137aa9a8ec4ae7fe65b3ef2bdb8736c1d5040c2b98c97300090`。
Debug 与 Release 均构建成功；最终测试使用 Release。
工具链为本地 Fx Studio 提供的 GCC 14.1.0 / fxSDK 2.11.0。

## 闭环证据

Minesweeper 在首次和重入测试中均保存了：

```text
SHA256_OK
GATES_PATCHED=00000002,A8062718
HANDOFF_PENDING
MAPPING_INSTALLED=0000001F,00000000
TARGET_ENTER
OS_CALLBACK=00000001,00000001
TARGET_EXIT_GUARD=00000000,00000000
MAPPING_RESTORED=00000000,00FC7501
CLEANUP=00000000,00000001
```

这一路中目标没有留下注册的退出回调，gint 在进入系统菜单前已执行自身退出。
另有完全自编的目标注册回调、返回 42，Loader 实际执行该回调并观察到它写入的
`08100004=1`，随后恢复映射、释放并正常退出；该测试没有跳过目标初始化或
把目标代码由调试器写进内存。

15 个原生边界用例通过：目标返回与回调、保守堆预算不足、context/image/runner
三阶段分配失败、BIN 校验失败、BIN 缺失、长度错误、profile 格式错误、patch
越界、patch 预期字不匹配、catalog 错误、profile 缺失、外部同名日志保护、
目标私有 RAM 冲突。每个拒绝路径均没有 `TARGET_ENTER`，可以 EXIT 退出。
这不是完整故障恢复测试，也未覆盖目标崩溃后自动接管。

CPU 回归、13 组运行时测试、15 组硬件模型测试、8 组 profile 测试通过。
本地整套回归首次运行时，已有 ALPHA 锁定按键测试曾出现一次时序失败，独立复跑
及后续整组复跑通过；未修改实现来吞掉失败。样本测试脚本增加了调试器恢复执行
后的状态同步，避免把尚未消费的继续命令误判成目标停机。

## 退出阻断的具体位置

Wolf 的原镜像 `00309F68` 为 `mov.l @(PC),r0; jmp @r0; nop`，常量池
`00309F70` 为 `A0000000`。这是可证明的直接控制转移，不能当成一般可平移的
地址或正常 `main` 返回。模拟器在该 ROM 区没有固件，执行报错；Loader 的
profile 现在报告这个未适配路径，尚未改写它。实机上的完整效果未测，不能
称为安全返回菜单。

Fruit 的退出函数在 `00308432` 调用 `0x01E7`。本机关联移植源码把它注释为
退出清理，但没有足够的 OS 语义依据完成实现。本轮继续明确报未知调用，未
用空返回值掩盖；原程序和 Loader 都停在同一位置。其他菜单路径及长期运行
仍需继续验证。

## 模拟器修正与下一道底层门槛

补齐了 gint 所用 `PutKeyCode(4,9,0)` → `GetKeyWait(menu=0)` 的 HLE 菜单路径，
以及键盘缓冲清除。保留 `PutKey(30003)` 原样返回的实测行为。新路径依据
gint `src/kernel/osmenu.c` 及接口语义，不冒充已取得新一轮实机测量。

下一项关键工作是取得 fx-9860GIII 上可验证的存储文件物理分片/映射方法，
在有限 RAM 与 TLB 下维持 KhiCAS 原地址空间；还要保证目标的私有内存区域和
退出清理。CG/Prizm 的文件块地址接口不能直接当作 FX 上存在的接口使用。
参见 [fx 文件块映射讨论](https://www.casiopeia.net/forum/viewtopic.php?f=11&t=1742)。
目前没有把未知文件映射、任意 guest 缺页处理、copy-back 数据缓存或完整 OS
实现为已验证功能。因此结论是“小程序原地址映射方案已有运行证据”，而不是
“任意 G1A 的底层已经全部打通”。
