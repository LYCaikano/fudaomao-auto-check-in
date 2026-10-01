# fudaomao-auto-check-in

兰州大学辅导猫查寝一键签到脚本。

## 使用

```bash
pip install -r requirements.txt   # cryptography 必需；pillow+numpy 用于照片扰动
cp config.example.json config.json   # 填入校园卡号和密码
python3 run.py
```

拍照任务需要事先把一张或多张宿舍照片（jpg/png）放进 `pic/`。

## 支持情况

| 签到方式 | 状态 |
|---|---|
| 定位 + 拍照 | 支持，已验证 |
| 纯定位 | 支持，已验证 |
| 免签/登记制任务（registerLeaveTasks） | 时段内会尝试提交，未充分验证 |
| 风控验证码触发时空 ticket 绕过 | 有时能过，未验证 |
| 扫码（signMode 1/2/4） | 不支持，跳过并提示 |
| IoT 设备（signMode 3） | 不支持，跳过并提示 |
| NFC（signMode 5） | 不支持，跳过并提示 |

## 行为

- 每次运行先检查登录状态：本地会话（`cookies.txt`）有效直接用；失效则用 `session.json` 的令牌重跑认证链；令牌也被顶就账密重登，短信验证码手动输一次。device_id 固定，正常长期不需要验证码
- 非交互运行（cron 等）先随机延迟，上限由 config.json 的 `jitter_max_seconds` 控制（默认 0）；手动运行立即开始
- 自动找当前时段内的未签/登记任务；已签、未开始、已结束的不动
- 定位取任务围栏圆内随机一点（收缩到 80% 半径避开边界）
- 拍照任务从 `pic/` 随机选一张，扰动重编码（去 EXIF、防查重）后 OSS 直传提交；无 pillow/numpy 时原样上传

## 文件

| 文件 | 说明 |
|---|---|
| `run.py` | 程序入口 |
| `requirements.txt` | Python 依赖 |
| `config.json` | 账号配置（校园卡号/密码；`jitter_max_seconds` 定时随机延迟上限） |
| `pic/` | 签到照片，随机选一张 |
| `session.json` | 持久化登录令牌与设备 ID（自动生成） |
| `cookies.txt` | fdm 会话 Cookie（自动生成） |

## 原理备注

- 登录：网关 `loginV2`（AES-CBC，key=IV 硬编码于 App）→ 短信二次认证 → `getSt` 换 ST → fdm 302 认证链落 `MOD_AUTH_CAS`
- 接口信封 `{"code":"0","datas":{...}}`；会话脱钩时返回空壳 `WEC-HASLOGIN:false`，识别后自动重建会话重试
- 风控 `checkValidation` 按需触发 PicCheck 点选识图验证码，验证结果作为 `submitSign.ticket`
