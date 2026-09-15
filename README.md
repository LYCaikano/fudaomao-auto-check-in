# fudaomao-auto-check-in

兰州大学辅导猫查寝一键签到脚本。

## 使用

```bash
pip install -r requirements.txt   # cryptography 必需；pillow+numpy 用于照片扰动
cp config.example.json config.json   # 填入校园卡号和密码
# 把一张或多张签到照片（宿舍自拍等，jpg/png）放进 pic/
python3 run.py
```

到点直接 `python3 run.py` 即可。可用 cron / systemd timer 定时跑。

## 行为

- 每次运行先检查登录状态：
- 非交互运行（cron 等）会先随机延迟，上限由 config.json 的 `jitter_max_seconds` 控制（默认 0 即不延迟，本地部署建议设为 500 模拟真人操作）；手动运行（tty）立即开始
  1. 本地 fdm 会话（`cookies.txt` 的 `MOD_AUTH_CAS`）有效 → 直接用
  2. 失效 → 用 `session.json` 里持久化的 `login_token/gateway_token` 重跑认证链
  3. token 也被顶 → 账密重新登录；触发二次认证时短信验证码**手动输入**一次
- 固定 device_id + 令牌持久化，正常情况长期不需要验证码
- 自动找当前时段内的未签/登记任务；已签、未开始、已结束的不动
- 定位：取任务围栏（signPlaceSelected）圆内随机一点（收缩到 80% 半径避开边界）
- 拍照签到任务：从 `pic/` 随机选一张，先做自然化扰动（几何微缩放 + 光度抖动 + 亮度自适应高斯噪声 + 随机质量重编码，去 EXIF），OSS 直传后提交；无 pillow/numpy 时原样上传
- 扫码 / IoT / NFC 任务无法脚本化，会跳过并提示
- 触发风控验证码时会先尝试空 ticket 直接提交（可能直接通过）；失败才需手动到企业微信完成

## 文件

| 文件 | 说明 |
|---|---|
| `run.py` | 程序入口，一键签到 |
| `requirements.txt` | Python 依赖清单 |
| `config.json` | 账号配置（`username`/`password` = 校园卡号/密码；`jitter_max_seconds` = 定时运行随机延迟上限，默认 0） |
| `pic/` | 签到照片，一张或多张，程序随机选择 |
| `session.json` | 持久化登录令牌与设备 ID（自动生成） |
| `cookies.txt` | fdm 会话 Cookie（自动生成） |

## 原理备注

- 登录：网关 `loginV2`（AES-CBC，key=IV 硬编码于 App）→ 短信二次认证 → `getSt` 换 ST → fdm 302 认证链落 `MOD_AUTH_CAS`
- 接口信封 `{"code":"0","datas":{...}}`；识别了「会话脱钩空壳响应」（`WEC-HASLOGIN:false`）等失效形态，自动重建会话重试
- 风控校验 `checkValidation` 为服务端按需触发，弹出的是 wisedu 自家 PicCheck 点选识图验证码（非滑块），验证结果作为 `submitSign.ticket`
