# KRW MASTER ROADMAP（单文件接力图 · 蒸馏自 34 波 journal · 2026-10-25）
> 目标：iPhone12,1 / iOS 26.0.1（904.76.7）/ AppleAVE2UserClient → 内核读写
> 当前完成度：结构逆向 ~95%。剩余 = 3 块拼图 + 上机实证。**未达成 KRW。**

## 0. 已验证的攻击面（不要重查）
- sel1 create（in 0x6f0）/ sel3 async（ wake port SEND right 必须）/ sel4 configure（in 0x1a0a0，MS 8 项 patch 全通）——全部 KERN_SUCCESS 稳定。
- sel5 IO_Start（in 0x1a0b0 = 0x30 命令头 +0x04=5/+0x10/+0x18/+0x20/+0x28=SID + 载荷@+0x30）——恒 -1015。
- sel2=reset 非 free；sel12/13=-1002；sel6=-1015；sel7-10=-1011。
- 设备：SSH root/0 @127.0.0.1:2222（paramiko，OpenSSH 客户端不可用）；探针 v57 在 /var/root（e_root.plist 签名）；frida 17.16.4 注入对 iOS 26 全废（iOS server 已停发，无升级路径）。

## 1. sel5 -1015 完整因果链（每环 foff 级证据）
```
sel5 → executor 0x1b9d924（门：UC+0xd8/0x100/0x160 非空——已过）
  → 0x1b9dd60: Configure(x0=[UC+0x160]=pool, x1=&in[0x18], x2=SID, x3=in+0x1a0a8, x4=&in[0x22c], x5=&in[0x340], x6=&in[0x2c])
  → 门链 0x1a77104 → 0x1B80288（池条目校验，空容器直通）→ 0x1b81f78 → 全过
  → InitUCInfoPool 0x1a7211c（0x1a7224c bl 0x1b671c0 查表：
      owner=[[pool+0x40]+0x18]=IOSurfaceRoot, key=cookie=0xfffffff00aa9f8d0（WorkPool 全局单例地址）
      → IOSurfaceRoot 表查 key=cookie → **条目不存在 → -1015**（失败被吞，InitUCInfoPool 返回 0）
  → Configure 后段其它 -1015 点报出（0x1a72d58 等待重校口径）
```
**根因**：key=cookie 的注册条目不存在。注册者 = WorkThread 命令执行链。

## 2. 注册链（全部定位，缺触发）
```
WorkPool 对象 = [UC+0xe0]（create 深链 0x1b02f60 构造，kalloc 0x7bd51f0，init 0x1b2c060 注册全局 0xaa9fb58）
WorkPool init = 0x1b25d50（tag 0x5b；清 [WorkPool+0xc8] 入队器槽）
[session+0x20] = [UC+0xe0] 值（pool init `stp x20,x21,[x19,#0x18]` 第二槽）
[WorkPool+0x88] = cmd 条目数组（0x1a70008 从 [session+0x2d0] 容器物化；容器出生 0x1a7928c）
0x1ba9814 = 内核线程入口（WorkThread 主循环；零 bl/零 vtable/零 adrp 引用——thread_create 传递）
  内部：0x1ba9c28 装 provider（getter 0x1ac2628，provider 来源未解 ← 剩余拼图①）
        0x1bae7b4 自举三组件（[self+0x98]→+0x30 入队器/+0x88/+0x98，缺一失败）
        命令执行 → cmd5 → 0x1abeb5c 创建+注册（0x1ad9c20 → 0x1a70008 物化）→ 0x1b66980
cmd5 入队 = 0x1BAE3DC（Configure 0x1a7c710 块，门 0x1a77104 过后）
  → [WorkPool+0xc8] 子对象 vtable+0xe8 方法 → 返回非 0 = 入队失败 ← 剩余拼图②
```

## 3. 剩余三块拼图（按序执行）
1. **0x1ac2628 provider getter 失败条件**（核心 0x1ac640c 后段，读 [self+0x78]/[+0x68]，tag 0x52/0x53 日志）——判定我们的调用序列下 provider 为何缺失/无效。
2. **[WorkPool+0xc8] 入队器 vtable+0xe8 实现定位**（构造候选 0x1b01608 kalloc 0x7bd5eb0；注意 0x1b25d50 是 WorkPool init 非入队器构造——w13 已排除）→ 读失败条件。
3. **触发构造上机**：provider+三组件就位 → cmd5 入队成功 → WorkThread 执行 → 注册 → **sel5 返回码族变化（-1015→-1022/-1001/0）**→ LRB 回绕配方（configure payload 0x22c-0x278 窗：flags=1, B=C=0x10000, D=E=4 → 0x40005 vs 4GB）→ 溢出实证 → KRW。

## 4. 上机快速判定工具
- ID 探针：`AVE2_ID_PROBE=1 AVE2_P5_DELAY_MS=4000`（v57）——sel4 后窗口 IOSurface 分配 delta（=1 探针自身 = 无注册活动）。
- 返回码翻译（0x1b926d0）：-1001→c2、-1002→c7、-1011→d9、-1015→0xe0000001、-1022 新见。
- 污染警报：单次 -1001 HIT 不可复现（周期性内核噪声 ~0.13%），必须 A/B 对照。
- 对照基线：`AVE2_TEST=pwr5 AVE2_PWR_SEQ=0 AVE2_S5SID=1 AVE2_MS_PATCH='0x2FFC:1;0x3130:2;0x312C:2;0x36F4:0;0x36F8:0;0x5A0:0;0x6860:0;0x6864:0'` → sel5 恒 0xe0000001。

## 5. 已排除的死路（不要重走）
- sel5 SID=IOSurface ID（444 实测否定）；create 注入 key（版本串硬校验）；scalar 前置（pwr5 13 组阴性）；延迟窗 3s/8s（阴性）；create mode 2/3（阴性）；0x1b910c8=SID 校验器（实为帧号比较）；sel5 设计死锁（IOSurfaceRoot 表是全局的，非 AVE2 私有）；0x8656ec4=构造（实为 typed release）；MBInputCtrl 路径（26.0.1 不活跃）。

## 6. 关键换算/工具
- **foff = vm_disp - 0xfffffff007004000**（kdis 显示口径；已三次踩坑）
- kdis.py（ZCode 工作区）：show/xref/str/vm2f；kernelcache_research_26.0.1.bin 为基准
- vtable 槽搜索：PAC 签名指针需 46 位 mask（本轮 0 命中——0x1ba9814 是线程入口非 vtable 方法）
- 0x8656cd0=alloc、0x8656ec4=typed release；WorkPool 类方法群 0x1b25d50..0x1b2c500

## 7. 备选攻击面（主线堵死时）
- LRB mode-5 dispatch 路由（FIRE_READY §6 未解：哪个 session 字段路由到 FUN_4ccdac）
- capability 表绕过（26.0.1 的表内容未 dump）
- 26.5.2 kernelcache（905.36.1，本地有 bin 未抽 kext）
- iOS 27 参考材料（参考/Ping-2o/）——b2→b4 修复面 = 22 个计算器，26.0.1 全裸
