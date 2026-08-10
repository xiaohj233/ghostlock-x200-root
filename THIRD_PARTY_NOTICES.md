# THIRD_PARTY_NOTICES

This file lists third-party code and references relevant to GhostLock-X200.
It is a transparency measure; legal obligations are governed by the
licenses named here and in NOTICE. Nothing is fabricated: entries whose
license could not be verified are marked UNKNOWN/TODO.

## Code included in this repository (or in Release assets)

1. **NebuSec / CyberMeowfia — IonStack (CVE-2026-43499)**
   - URL: https://github.com/NebuSec/CyberMeowfia
   - Revision: 2c83bfb0c9230dc063e1bbfc3e06228d45dd938f
   - License: Apache-2.0
   - Verbatim copies: exploit/src/pipe.c, preload.c, root.c, su_blob.S,
     wallpaper_blob.S, assets/wallpaper.webp
   - Derived: exploit/src/common.h, fops.c, main.c, slide.c, util.c,
     su_daemon.c, target_x200.h, standalone_main.c
   - Vendored: exploit/vendored/offset.h, exploit/vendored/kernelsnitch/ (kernelsnitch.h =
     local build variant, derived)

2. **boxiaolanya2008 / CVE-2026-43499-Neo11Plus**
   - URL: https://github.com/boxiaolanya2008/CVE-2026-43499-Neo11Plus
   - Revision: babd8dcad5b1f4537e81953e8b105f94b4e9440e
   - License: Apache-2.0
   - Use: adaptation reference; slide.c/util.c/common.h partially same-origin

3. **YuKongA / ghostlock-app**
   - URL: https://github.com/YuKongA/ghostlock-app
   - Revision: b4fdb1f2f439004f9739371f52b69653fbfd8db1
   - License: Apache-2.0
   - Use: GL_TASK_W2 write-shape concept (local reimplementation in
     slide.c); perf-sampling leak idea for w2host.c (independent
     implementation, see w2host.c file header)

4. **tiann / KernelSU v3.2.5** (kernel module shipped in-tree; ksud Release asset)
   - URL: https://github.com/tiann/KernelSU
   - Revision: v3.2.5 @ b0bc817b4e966aa6aa830834eaf6ef765d821d40
   - License: userspace ksud = GPL-3.0-or-later; kernel/ = GPL-2.0-only
   - Included:
     - prebuilt/ksud (Release asset; unmodified libksud.so from the official
       APK, SHA256
       077797B6CD07621B4352A55BBCFB03CB86A33F0FB044AEB4706445A21215EB57)
   - modules/kernelsu/kernelsu.ko (shipped in-tree; official v3.2.5 release
     asset android15-6.6_kernelsu.ko [SHA256 5933ECA4...] + vermagic rewrite
     for the X200 b57 kernel via modules/kernelsu/patch_vermagic.py; adapted
     SHA256 187BB1BD4732DD1E193C09E1BA35A5D3A2B35190B32AABF3F2F7B0CDB03A71FB)
     - corresponding source: official kernel/ @ b0bc817b
       (https://github.com/tiann/KernelSU, GPL-2.0-only)

## Original code (project-owned, not third-party)

- `modules/permissive_restore/` — original GhostLock-X200 kernel module, licensed
  **GPL-2.0-only** (see `LICENSES/GPL-2.0-only.txt`); `MODULE_LICENSE("GPL")`
  matches. Listed here only for license transparency.
- `exploit/src/w2host.c` — project-owned; its perf-sampling leak idea is
  drawn from ghostlock-app / GhostLock-for-OnePlus (Apache-2.0, see item 3
  and NOTICE), implementation is independent; attribution in file header.

## Not distributed (removed for compliance)

- tools/payload_dumper.py — upstream (vm03/payload_dumper) has no license;
  removed from distribution.
- prebuilt/android15-6.6_kernelsu.ko — originally removed because its
  binary-to-source chain could not be verified (digest 187BB1BD differs from
  the official release digest 5933ECA4). The chain was later fully recovered
  from the development log (session 019fcfc8-..., 2026-08-09): official
  v3.2.5 asset + vermagic rewrite (modules/kernelsu/patch_vermagic.py
  reproduces 187BB1BD exactly; BuildID b61aef7e confirms same origin).
  It is now shipped in-tree as modules/kernelsu/kernelsu.ko (see item 4).

## Research references (no code included)

- p2p3p/GhostLock-for-OnePlus (no LICENSE; architecture inspiration)
- JoinChang/ghostlock-oneplus (no LICENSE)
- CatXiaoShi/cve-2026-43499 (vivo PD2425 X200 Pro same-platform adaptation
  reference: target.h / slide.c / root.c / util.c / su_daemon.c analysis,
  vr.ko anti-root mechanism; license UNKNOWN - TODO; no expression-level
  code included per provenance audit)
- soralis0912/CVE-2026-43499-aristotle (no LICENSE)
- PeronGH/ghostlock-selinux-disabler (Apache-2.0)
- Petalrain224/CVE-2026-43499-Redmi-Turbo5 (GPL-3.0)
- Linuxoid-cn/CVE-2026-43499-Poc-Analysis (UNKNOWN - TODO)
- 2932796375github/CVE-2026-43499_OPPO-MT6835 (UNKNOWN - TODO)
- oopnv70-lab/ghostlock-honor-aak (UNKNOWN - TODO)
- Neorestim/NeoRoot (GPL-3.0; preload.so disassembly reference)
- ReSukiSU/SukiSU, SukiSU-Ultra (GPL-3.0)
- JerryTse-OSS/VIVO-OTA-Tracker (see upstream)
- hexo141/Rootme (see upstream)
