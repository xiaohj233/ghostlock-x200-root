# SOURCE-URLS — external / upstream sources

Only sources that are actually required or directly relevant are listed.
Revisions are pinned where determinable.

| Artifact / dependency | Source | Revision / identity | How to obtain |
|---|---|---|---|
| adb (platform-tools) | https://developer.android.com/tools/releases/platform-tools | any recent | download from the official Android site |
| Python 3 | https://www.python.org | >= 3.10 | official installer |
| capstone / pyelftools | https://pypi.org/project/capstone/ , https://pypi.org/project/pyelftools/ | any recent (see tools/offset_tools/requirements.txt) | pip install -r tools/offset_tools/requirements.txt |
| Android NDK (clang) | https://developer.android.com/ndk | r25+ (aarch64-linux-android28) | official NDK download |
| KernelSU v3.2.5 (ksud userspace; kernel module) | https://github.com/tiann/KernelSU | v3.2.5 @ b0bc817b4e966aa6aa830834eaf6ef765d821d40 | shipped ko = official release asset android15-6.6_kernelsu.ko (SHA256 5933ECA4) + vermagic rewrite for X200 b57 (modules/kernelsu/patch_vermagic.py -> 187BB1BD); corresponding source = official kernel/ @ commit; ksud from official release APK |
| IonStack (vendored offset.h + kernelsnitch/) | https://github.com/NebuSec/CyberMeowfia | 2c83bfb0c9230dc063e1bbfc3e06228d45dd938f | vendored in-repo (Apache-2.0) |
| vivo b57 kernel source (for permissive_restore.ko rebuild) | vivo OTA / vendor | 6.6.89 b57af212129c (not distributed) | user-provided; see README |
| Payload extraction tool (boot.img -> kernel ELF) | a separately installed, appropriately licensed tool | not bundled by design | see README "Adapting other builds" |
