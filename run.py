#!/usr/bin/env python3
"""辅导猫（fdm.lzu.edu.cn 查寝签到）一键签到脚本

用法：python3 run.py

- 账号配置在 config.json（username/password = 校园卡号/密码）
- pic/ 文件夹放一张或多张签到照片（jpg/png），拍照签到任务随机选一张提交
- 定位：取任务签到范围内（地理围栏）随机一点提交
- 登录逻辑复刻自兰大 App 本体源码（loginV2 AES + 短信二次认证），
  login_token/gateway_token 持久化在 session.json，fdm 会话 Cookie 持久化在
  cookies.txt —— 会话有效时不再触发短信验证码；失效重登时才需手动输入验证码

逆向依据：~/lzuapp/analysis/FDM_API_REPORT.md、
~/lzuapp/kcb-app 中的 FdmApi.kt / FdmRepository.kt / LzuApi.kt / LzuCrypto.kt
"""
import http.cookiejar
import json
import math
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
SESSION_PATH = os.path.join(BASE_DIR, "session.json")
COOKIES_PATH = os.path.join(BASE_DIR, "cookies.txt")
PIC_DIR = os.path.join(BASE_DIR, "pic")

GATEWAY = "https://gateway.lzu.edu.cn:9000"
FDM_BASE = "https://fdm.lzu.edu.cn/wec-counselor-attendance-apps"
FDM_ENTRY = FDM_BASE + "/student/mobileStudent/index.html"
UA = "Mozilla/5.0 (Linux; Android 15; wv) MicroMessenger/8.0.47"

# 兰大 App 硬编码 AES 密钥（key = IV），见 kcb-app util/LzuCrypto.kt
AES_KEY = b"QSfg26hg433BV42a"

CTX = ssl.create_default_context()

PIC_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".bmp")


def log(msg):
    print(time.strftime("[%H:%M:%S]"), msg, flush=True)


class AuthError(Exception):
    """会话/登录态失效（可重跑认证链或重登录恢复）"""


class ApiError(Exception):
    """业务/网络错误"""


# ---------- AES（AES/CBC/NoPadding，零填充，hex 小写） ----------

def aes_encrypt_hex(plain: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    raw = plain.encode("utf-8")
    if len(raw) % 16:
        raw += b"\x00" * (16 - len(raw) % 16)
    enc = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_KEY)).encryptor()
    return (enc.update(raw) + enc.finalize()).hex()


def aes_decrypt_hex(hexstr: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_KEY)).decryptor()
    return (dec.update(bytes.fromhex(hexstr)) + dec.finalize()).rstrip(b"\x00").decode("utf-8", "replace")


# ---------- 配置与持久化 ----------

def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({"username": "", "password": ""}, f, ensure_ascii=False, indent=2)
        sys.exit("已创建 config.json 模板，请填入校园卡号(username)和密码(password)后重跑")
    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)
    if not cfg.get("username") or not cfg.get("password"):
        sys.exit("config.json 中 username/password 为空，请填写校园卡号和密码")
    return cfg


class SessionStore:
    """持久化 device_id + login_token/gateway_token（防每次都要短信验证码）"""

    def __init__(self):
        self.device_id = ""
        self.login_token = ""
        self.gateway_token = ""
        if os.path.exists(SESSION_PATH):
            try:
                with open(SESSION_PATH, encoding="utf-8") as f:
                    d = json.load(f)
                self.device_id = d.get("device_id", "")
                self.login_token = d.get("login_token", "")
                self.gateway_token = d.get("gateway_token", "")
            except Exception as e:
                log("session.json 读取失败（%s），将重新生成" % e)
        if not self.device_id:
            # 与 App 一致的设备标识形态；固定不变可降低二次认证概率
            self.device_id = str(uuid.uuid4())
            self.save()

    @property
    def has_tokens(self):
        return bool(self.login_token and self.gateway_token)

    def save(self):
        tmp = SESSION_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({
                "device_id": self.device_id,
                "login_token": self.login_token,
                "gateway_token": self.gateway_token,
            }, f, ensure_ascii=False, indent=2)
        os.replace(tmp, SESSION_PATH)


# ---------- 兰大网关（登录 / 短信二次认证 / ST 票据） ----------

def _http(req: urllib.request.Request, timeout=15) -> str:
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        raise ApiError("网络错误: %s" % e)


def gateway_login(username: str, password: str, store: SessionStore):
    """loginV2 密码登录；code=20001 时短信二次认证（验证码手动输入）。
    成功把 login_token/gateway_token 写入 store。"""
    body = json.dumps({"app_os": 2, "name": username, "pwd": password,
                       "device_id": store.device_id, "divece_system": "15"},
                      separators=(",", ":"))
    req = urllib.request.Request(
        GATEWAY + "/eusp-unify-terminal/app-user/loginV2",
        data=aes_encrypt_hex(body).encode(),
        headers={"Content-Type": "application/json;charset=UTF-8",
                 "Transfer-Encrypt": "true"})
    resp = json.loads(aes_decrypt_hex(_http(req)))
    code = resp.get("code")
    if code == 20001:
        log("需要短信二次认证，正在发送验证码…")
        sid = (resp.get("data") or {}).get("session_id") or ""
        if not sid:
            raise ApiError("loginV2 未返回 session_id: %s" % resp)
        _gateway_form("/eusp-unify-terminal/app-user/sendPhoneCaptcha",
                      {"deviceId": store.device_id, "sessionId": sid})
        log("验证码已发送到绑定手机")
        try:
            captcha = input("请输入短信验证码: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise ApiError("未输入验证码，已取消登录")
        vr = _gateway_form("/eusp-unify-terminal/app-user/verifyPhoneCaptcha",
                           {"deviceId": store.device_id, "sessionId": sid,
                            "appOs": "1", "captcha": captcha})
        data = vr.get("data") or {}
    elif code == 1:
        data = resp.get("data") or {}
    else:
        raise ApiError("登录失败: code=%s %s" % (code, resp.get("message")))
    store.login_token = data.get("login_token") or ""
    store.gateway_token = data.get("gateway_token") or ""
    if not store.has_tokens:
        raise ApiError("登录响应缺少 token: %s" % data)
    store.save()
    log("登录成功（token 已持久化到 session.json）")


def _gateway_form(path: str, params: dict) -> dict:
    req = urllib.request.Request(GATEWAY + path,
                                 data=urllib.parse.urlencode(params).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    r = json.loads(_http(req))
    if r.get("code") != 1:
        raise ApiError("%s 失败: %s %s" % (path, r.get("code"), r.get("message")))
    return r


def get_st(store: SessionStore, service: str = "") -> str:
    """用 login_token/gateway_token 向网关换 ST 票据（响应 AES 加密）"""
    q = urllib.parse.urlencode({"loginToken": store.login_token,
                                "serviceId": "", "service": service})
    req = urllib.request.Request(
        GATEWAY + "/eusp-unify-terminal/app-user/getSt?" + q,
        headers={"Authorization": store.gateway_token, "Transfer-Encrypt": "true"})
    resp = json.loads(aes_decrypt_hex(_http(req)))
    if resp.get("code") != 1 or not resp.get("data"):
        raise AuthError("getSt 失败（login_token 已失效）: %s" % resp.get("message"))
    return resp["data"]


# ---------- 辅导猫客户端 ----------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class FdmClient:
    """fdm 会话 = Cookie MOD_AUTH_CAS（LWPCookieJar 落盘 cookies.txt 持久化）"""

    def __init__(self):
        self.jar = http.cookiejar.LWPCookieJar(COOKIES_PATH)
        if os.path.exists(COOKIES_PATH):
            try:
                self.jar.load(ignore_discard=True, ignore_expires=True)
            except Exception as e:
                log("cookies.txt 读取失败（%s），将重新建立会话" % e)
        self.opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=CTX))

    def save_cookies(self):
        try:
            self.jar.save(ignore_discard=True, ignore_expires=True)
        except Exception as e:
            log("cookies 保存失败: %s" % e)

    def has_session(self) -> bool:
        return any(c.name == "MOD_AUTH_CAS" for c in self.jar)

    def clear_session(self):
        self.jar.clear()
        self.save_cookies()

    # --- 认证链（见 FDM_API_REPORT.md §1，复刻 FdmApi.fdmLogin） ---

    def _get(self, url: str):
        """无重定向 GET，返回 (HTTP code, Location)"""
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with self.opener.open(req, timeout=15) as r:
                return r.status, r.headers.get("Location")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location")

    def login_chain(self, store: SessionStore):
        """入口页 302 链 -> 网关 getSt 换 ST -> loginSuccess 落 MOD_AUTH_CAS"""
        self.jar.clear()
        code, loc = self._get(FDM_ENTRY)
        if not loc:
            raise ApiError("查寝服务入口异常(%s)" % code)
        iap = urllib.parse.urljoin(FDM_ENTRY, loc)
        code, loc = self._get(iap)
        if not loc:
            raise ApiError("查寝认证跳转异常(%s)" % code)
        m = re.search(r"[?&]service=([^&]+)", urllib.parse.urljoin(iap, loc))
        if not m:
            raise ApiError("查寝认证参数缺失")
        svc = urllib.parse.unquote(m.group(1))
        st = get_st(store, svc)  # login_token 失效会抛 AuthError
        _, loc = self._get(svc + "&ticket=" + urllib.parse.quote(st))
        if loc:
            self._get(urllib.parse.urljoin(svc, loc))
        if not self.has_session():
            raise AuthError("查寝登录失败（未获得 MOD_AUTH_CAS）")
        self.save_cookies()
        log("fdm 认证链完成，会话已建立")

    # --- 业务接口（信封 {"code":"0","datas":...}） ---

    def api(self, path: str, body: dict) -> dict:
        data = json.dumps(body, separators=(",", ":")).encode()
        req = urllib.request.Request(FDM_BASE + path, data=data, headers={
            "User-Agent": UA,
            "Content-Type": "application/json;charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest"})
        try:
            with self.opener.open(req, timeout=20) as r:
                text = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                raise AuthError("会话失效(HTTP %d)" % e.code)
            raise ApiError("HTTP %d" % e.code)
        obj = json.loads(text) if text.lstrip().startswith("{") else None
        if obj is None:
            raise AuthError("会话失效（非 JSON 响应）")
        datas = obj.get("datas")
        # 会话脱钩金丝雀：服务端返回 code=0 空壳 {"WEC-HASLOGIN":false,...}
        if isinstance(datas, dict) and str(datas.get("WEC-HASLOGIN")) == "false":
            raise AuthError("会话失效（空壳响应）")
        if str(obj.get("code")) != "0":
            msg = obj.get("message") or "操作失败"
            code = str(obj.get("code"))
            if re.fullmatch(r"[0-9A-Fa-f]{32}", code) or any(
                    w in msg for w in ("登录", "权限", "失效")):
                raise AuthError(msg)
            raise ApiError(msg)
        return datas if isinstance(datas, dict) else {"_raw": datas}

    # --- 具体接口 ---

    def interval_months(self):
        return self.api("/student/attendance/getStuIntervalMonths", {})

    def running_tasks(self):
        return self.api("/student/attendance/getStuAttendacesInOneDay", {})

    def detail(self, sign_instance_wid: str, sign_wid: str):
        return self.api("/student/attendance/detailSignInstance",
                        {"signInstanceWid": sign_instance_wid, "signWid": sign_wid})

    def check_validation(self) -> bool:
        d = self.api("/student/attendance/checkValidation",
                     {"deviceId": "", "qrUuid": ""})
        return d.get("validation") is True

    def upload_photo(self, jpeg: bytes) -> str:
        """getUploadPolicy -> OSS multipart 直传 -> previewAttachment 取 URL"""
        policy = self.api("/student/attendance/getUploadPolicy", {"fileType": 1})
        host, form = policy.get("host", ""), policy.get("formData") or {}
        if not host or not form:
            raise ApiError("获取上传凭证失败")
        file_name = policy.get("fileName") or "photo"
        content_type = policy.get("contentType") or "image/jpeg"
        boundary = "----fdm" + uuid.uuid4().hex
        parts = []
        for k, v in form.items():
            parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                          % (boundary, k, v)).encode())
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"file\"; "
                      "filename=\"%s.png\"\r\nContent-Type: %s\r\n\r\n"
                      % (boundary, file_name, content_type)).encode())
        parts.append(jpeg)
        parts.append(("\r\n--%s--\r\n" % boundary).encode())
        req = urllib.request.Request(host, data=b"".join(parts), headers={
            "User-Agent": UA,
            "Content-Type": "multipart/form-data; boundary=" + boundary})
        _http(req, timeout=60)
        r = self.api("/student/attendance/previewAttachment", {"ossKey": form.get("key", "")})
        url = r.get("_raw") if r.get("_raw") else r.get("url", "")
        if not url:
            raise ApiError("获取照片地址失败")
        return url

    def submit_sign(self, sign_instance_wid, lng, lat, photo_url, position):
        self.api("/student/attendance/submitSign", {
            "signInstanceWid": sign_instance_wid,
            "longitude": lng, "latitude": lat,
            "isMalposition": 0, "abnormalReason": "",
            "signPhotoUrl": photo_url, "position": position,
            "ticket": "", "uaIsCpadaily": False, "deviceId": "",
            "systemName": "", "systemVersion": "", "model": "",
        })


# ---------- 签到辅助 ----------

def in_window(begin: str, end: str) -> bool:
    try:
        b = time.mktime(time.strptime(begin, "%Y-%m-%d %H:%M"))
        e = time.mktime(time.strptime(end, "%Y-%m-%d %H:%M"))
    except (ValueError, OverflowError):
        return False
    return b <= time.time() <= e


def random_point_in_fence(fence: dict):
    """围栏圆内随机一点（收缩到 80% 半径内，避开边界抖动）"""
    lng, lat, radius = fence["lng"], fence["lat"], fence["radius"]
    r = radius * 0.8 * math.sqrt(random.random())
    theta = random.uniform(0, 2 * math.pi)
    dlat = r * math.cos(theta) / 111320.0
    dlng = r * math.sin(theta) / (111320.0 * math.cos(math.radians(lat)) or 1e-9)
    return round(lng + dlng, 6), round(lat + dlat, 6)


def pick_photo() -> bytes:
    """pic/ 下随机选一张；有 PIL 则重编码为 JPEG（与 App 行为一致，兼去 EXIF）"""
    files = [os.path.join(PIC_DIR, f) for f in os.listdir(PIC_DIR)
             if f.lower().endswith(PIC_EXTS)] if os.path.isdir(PIC_DIR) else []
    if not files:
        raise ApiError("pic 文件夹中没有图片，请放入签到照片后重跑")
    path = random.choice(files)
    log("随机选择照片: %s" % os.path.basename(path))
    try:
        import io
        from PIL import Image
        img = Image.open(path).convert("RGB")
        img.thumbnail((1600, 1600))
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=88)
        return buf.getvalue()
    except ImportError:
        with open(path, "rb") as f:
            return f.read()


def signable_tasks(datas: dict):
    """当前可签：未签/登记类任务且在签到时段内（分类以所在数组为准，见逆向报告 §4）"""
    out, seen = [], set()
    for key in ("unSignedTasks", "registerLeaveTasks"):
        for t in datas.get(key) or []:
            wid = str(t.get("signInstanceWid", ""))
            if wid in seen:
                continue
            if in_window(str(t.get("singleTaskBeginTime", "")),
                         str(t.get("singleTaskEndTime", ""))):
                seen.add(wid)
                out.append(t)
    return out


def do_sign(fdm: FdmClient, task: dict):
    name = task.get("taskName", "?")
    wid = str(task.get("signInstanceWid", ""))
    detail = fdm.detail(wid, str(task.get("signWid", "")))

    mode = int(str(detail.get("signMode", 0)) or 0)
    if mode in (1, 2, 4):
        log("「%s」需扫码签到，请到企业微信完成，跳过" % name)
        return
    if mode == 3:
        log("「%s」需 IoT 设备签到，请到企业微信完成，跳过" % name)
        return
    if mode == 5:
        log("「%s」需 NFC 签到，请到企业微信完成，跳过" % name)
        return

    fences = []
    for p in detail.get("signPlaceSelected") or []:
        try:
            fences.append({"lng": float(p["longitude"]), "lat": float(p["latitude"]),
                           "radius": float(p.get("radius") or 0),
                           "address": p.get("address", "")})
        except (KeyError, TypeError, ValueError):
            pass
    if not fences:
        log("「%s」详情无签到范围信息，跳过" % name)
        return

    if fdm.check_validation():
        # 风控点选验证码（PicCheck 识图，脚本无法自动完成）。但服务端未必强校验
        # ticket —— 不回退，先试一次空 ticket 直接提交，能过即绕过
        log("「%s」触发风控验证，尝试空 ticket 直接提交…" % name)

    fence = random.choice(fences)
    lng, lat = random_point_in_fence(fence)
    is_photo = str(detail.get("isPhoto", "0")) == "1"
    photo_url = fdm.upload_photo(pick_photo()) if is_photo else ""
    try:
        fdm.submit_sign(wid, lng, lat, photo_url, fence["address"])
    except ApiError as e:
        raise ApiError("%s（若本次触发了风控，则需到企业微信手动完成）" % e)
    log("「%s」签到成功 位置=%s(%f,%f)%s"
        % (name, fence["address"], lng, lat, " 已传照片" if is_photo else ""))


# ---------- 主流程 ----------

def ensure_session(fdm: FdmClient, store: SessionStore, username: str, password: str):
    """每次运行先检查登录状态：fdm 会话有效 → 直接用；
    否则用持久化 token 重跑认证链；token 也被顶 → 重新登录（可能要验证码）"""
    if fdm.has_session():
        try:
            fdm.interval_months()
            log("本地 fdm 会话仍有效，无需重新登录")
            return
        except AuthError:
            log("本地 fdm 会话已失效，重跑认证链")
    if store.has_tokens:
        try:
            fdm.login_chain(store)
            return
        except AuthError as e:
            log("认证链失败（%s），需要重新登录" % e)
    gateway_login(username, password, store)
    fdm.login_chain(store)


def main():
    random.seed()
    cfg = load_config()
    store = SessionStore()
    fdm = FdmClient()

    pics = [f for f in os.listdir(PIC_DIR) if f.lower().endswith(PIC_EXTS)] \
        if os.path.isdir(PIC_DIR) else []
    if not pics:
        log("提示: pic 文件夹为空，拍照签到任务需要放入至少一张照片")

    ensure_session(fdm, store, cfg["username"], cfg["password"])

    # 读操作网络抖动重试；签到提交不重试防重复
    datas = None
    for attempt in range(3):
        try:
            datas = fdm.running_tasks()
            break
        except AuthError:
            log("查询任务时会话失效，重建会话后重试")
            fdm.clear_session()
            ensure_session(fdm, store, cfg["username"], cfg["password"])
        except ApiError as e:
            if attempt == 2:
                raise
            log("查询任务失败（%s），重试中" % e)
            time.sleep(1)

    tasks = signable_tasks(datas or {})
    if not tasks:
        signed = len((datas or {}).get("signedTasks") or [])
        log("当前没有可签到的任务（今日已签 %d 项；任务未到时段或已结束）" % signed)
        return
    log("发现 %d 项可签到任务" % len(tasks))
    for t in tasks:
        try:
            do_sign(fdm, t)
        except AuthError:
            log("签到时会话失效，重建会话后重试一次")
            fdm.clear_session()
            ensure_session(fdm, store, cfg["username"], cfg["password"])
            try:
                do_sign(fdm, t)
            except (AuthError, ApiError) as e:
                log("「%s」签到失败: %s" % (t.get("taskName", "?"), e))
        except ApiError as e:
            log("「%s」签到失败: %s" % (t.get("taskName", "?"), e))
    fdm.save_cookies()


if __name__ == "__main__":
    try:
        main()
    except (AuthError, ApiError) as e:
        sys.exit("失败: %s" % e)
    except KeyboardInterrupt:
        sys.exit("已取消")
