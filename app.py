import gradio as gr
import os
import subprocess
import threading
import shutil
import spaces
import asyncio
import json
import time
import re
import base64

try:
    import psutil
except ImportError:
    subprocess.run(["pip", "install", "psutil"], capture_output=True)
    import psutil

WORKDIR = "/home/user/app/server"
os.makedirs(WORKDIR, exist_ok=True)


# ─── مسارات آمنة: منع Path Traversal ───────────────────────
def is_within_workdir(path: str) -> bool:
    """Return True if *path* resolves inside WORKDIR."""
    rp = os.path.realpath(path)
    wd = os.path.realpath(WORKDIR)
    return rp == wd or rp.startswith(wd + os.sep)


def normalize_relative_path(rel: str) -> str:
    """Collapse *rel*, strip leading ``/`` and ``..`` components, return safe relative path."""
    if not rel:
        return ""
    parts = [p for p in rel.replace("\\", "/").split("/") if p and p not in (".", "..")]
    return "/".join(parts)


def validate_simple_name(name: str) -> bool:
    """Return True if *name* contains no path separators or traversal sequences."""
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        return False
    return True


def resolve_safe_child_path(base_rel: str, child_name: str) -> str:
    """Return absolute path for *child_name* inside *base_rel*, or raise ``ValueError``."""
    base = os.path.realpath(os.path.join(WORKDIR, normalize_relative_path(base_rel)))
    if not validate_simple_name(child_name):
        raise ValueError(f"Invalid name: {child_name!r}")
    target = os.path.realpath(os.path.join(base, child_name))
    if not is_within_workdir(target):
        raise ValueError(f"Path escapes WORKDIR: {child_name!r}")
    return target


def sanitize_upload_name(name: str) -> str:
    """Strip directory components from an upload filename and validate."""
    name = os.path.basename(name)
    if not validate_simple_name(name):
        raise ValueError(f"Unsafe upload name: {name!r}")
    return name

log_output = []
mc_process = None

# ─── نظام الصلاحيات والمستخدمين ───
USERS_FILE = os.path.join(WORKDIR, "users.json")
PERMISSIONS = {
    "admin":  ["console", "start", "stop", "restart", "files_read", "files_write", "files_delete", "users_manage"],
    "editor": ["console", "files_read", "files_write"],
    "viewer": ["console", "files_read"],
}

def load_users():
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE) as f:
                return json.load(f)
    except: pass
    return {}

def save_users(users):
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
    except: pass

def get_user_role(username):
    if not username:
        return None
    users = load_users()
    return users.get(username, None)

# غيّر هذا لـ True فقط أثناء التطوير المحلي على جهازك الشخصي.
# إذا كان الـ Space عاماً (Public) أو ما فيه OAuth حقيقي، اتركه False دائماً
# وإلا أي زائر بدون هوية بياخذ صلاحيات كاملة (admin).
LOCAL_DEV_MODE = False


# ─── طلب المستخدم الحالي من الطلب ─────────────────────────
def resolve_current_user(request: gr.Request) -> str | None:
    """Extract the authenticated username from a Gradio ``Request`` object.

    Tries ``request.username`` (HF OAuth) then common headers/query params.
    Returns ``None`` when no identity can be determined.
    """
    if request is None:
        return None

    # Gradio on HF Spaces sets request.username when OAuth is active
    uname = getattr(request, "username", None)
    if uname:
        return uname

    # Fallback: X-Forwarded-User header (reverse-proxy setups)
    headers = getattr(request, "headers", {}) or {}
    forwarded = headers.get("x-forwarded-user") or headers.get("x-forwarded-preferred-username")
    if forwarded:
        return forwarded

    # Fallback: query parameter ``?user=xxx``
    query_params = getattr(request, "query_params", {}) or {}
    qp_user = query_params.get("user")
    if qp_user:
        return qp_user

    return None


# ─── تهيئة الأدمن الأولي ───────────────────────────────────
INITIAL_ADMIN_USERNAME = os.environ.get("INITIAL_ADMIN_USERNAME", "").strip()
ALLOW_FIRST_AUTHENTICATED_ADMIN = os.environ.get("ALLOW_FIRST_AUTHENTICATED_ADMIN", "").lower() in ("1", "true", "yes")


def _bootstrap_admin(username: str | None) -> None:
    """Ensure an initial admin exists in users.json.

    - ``INITIAL_ADMIN_USERNAME``: auto-adds this user as admin on first login.
    - ``ALLOW_FIRST_AUTHENTICATED_ADMIN``: the first user to authenticate gets admin.
    """
    if not username:
        return
    users = load_users()
    if users:
        return  # at least one user already configured — nothing to do
    candidate = INITIAL_ADMIN_USERNAME if INITIAL_ADMIN_USERNAME else (
        username if ALLOW_FIRST_AUTHENTICATED_ADMIN else None
    )
    if candidate:
        users[candidate] = "admin"
        save_users(users)
        log(f"[AUTH] Bootstrapped initial admin: {candidate}")

def has_perm(username, perm):
    if username is None:
        return LOCAL_DEV_MODE  # بدون هوية = بدون صلاحيات افتراضياً (أأمن)
    role = get_user_role(username)
    if role is None:
        return False
    return perm in PERMISSIONS.get(role, [])

# الحفاظ على استمرار تشغيل الـ Space وتنشيط الـ GPU
@spaces.GPU
def activate_gpu():
    return "[SYSTEM] GPU Activated."

def log(message):
    log_output.append(message)
    if len(log_output) > 400:
        log_output.pop(0)

_start_time = time.time()

def get_system_resources():
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        uptime_sec = int(time.time() - _start_time)
        days = uptime_sec // 86400
        hours = (uptime_sec % 86400) // 3600
        mins = (uptime_sec % 3600) // 60
        uptime_str = f"{days}d {hours}h {mins}m" if days else f"{hours}h {mins}m"
        return {
            "cpu": round(cpu, 1),
            "ram_used": round(mem.used / (1024**3), 1),
            "ram_total": round(mem.total / (1024**3), 1),
            "ram_pct": round(mem.percent, 1),
            "disk_used": round(disk.used / (1024**3), 1),
            "disk_total": round(disk.total / (1024**3), 1),
            "disk_pct": round(disk.percent, 1),
            "uptime": uptime_str,
        }
    except:
        return {"cpu": 0, "ram_used": 0, "ram_total": 4, "ram_pct": 0, "disk_used": 0, "disk_total": 20, "disk_pct": 0, "uptime": "0m"}

def get_online_players():
    try:
        joined = set()
        left = set()
        lines = log_output[-300:]
        for line in lines:
            m = re.search(r"(\S+)\s+joined the game", line)
            if m:
                joined.add(m.group(1))
            m = re.search(r"(\S+)\s+left the game", line)
            if m:
                left.add(m.group(1))
        return list(joined - left)
    except:
        return []

def send_console_command(cmd, user=None):
    if not has_perm(user, "console"):
        return "⛔ You don't have `console` permission"
    if not cmd or not cmd.strip():
        return "⚠️ Enter a command"
    if not (mc_process and mc_process.poll() is None):
        return "⚠️ Server is not running"
    try:
        mc_process.stdin.write(cmd.strip() + "\n")
        mc_process.stdin.flush()
        log(f"[CONSOLE] > {cmd.strip()}")
        return f"✅ Command sent: `{cmd.strip()}`"
    except Exception as e:
        return f"❌ Failed to send command: {e}"

def safe_download(url, dest_path, label, timeout=180):
    """
    ينزّل ملف من رابط مع معالجة أخطاء واضحة باللوجز.
    يرجع True/False. لو فشل، يمسح أي ملف فاضي (0 بايت) حتى ما يفكر
    باقي الكود إنه نزل بنجاح ويحاول يشغّله فيفشل بصمت.
    """
    try:
        result = subprocess.run(
            ["wget", "-q", "-O", dest_path, url],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0 or not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            log(f"[ERROR] فشل تحميل {label}: {result.stderr.strip()[:200] if result.stderr else 'رابط غير صالح أو استجابة فاضية'}")
            if os.path.exists(dest_path):
                os.remove(dest_path)
            return False
        log(f"[SYSTEM] تم تحميل {label} بنجاح.")
        return True
    except subprocess.TimeoutExpired:
        log(f"[ERROR] انتهت مهلة تحميل {label} (timeout).")
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return False
    except Exception as e:
        log(f"[ERROR] خطأ أثناء تحميل {label}: {e}")
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return False

# --- نظام إدارة تبعيات السيرفر تشغيل/إيقاف ---
def download_dependencies():
    if not os.path.exists(os.path.join(WORKDIR, "jdk")):
        jdk_tar = os.path.join(WORKDIR, "jdk.tar.gz")
        jdk_url = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.4%2B7/OpenJDK21U-jre_x64_linux_hotspot_21.0.4_7.tar.gz"
        if safe_download(jdk_url, jdk_tar, "Java 21 (JDK)"):
            try:
                subprocess.run(["tar", "-xzf", jdk_tar, "-C", WORKDIR], check=True, capture_output=True, text=True)
                for extracted in os.listdir(WORKDIR):
                    if extracted.startswith("jdk-21"):
                        os.rename(os.path.join(WORKDIR, extracted), os.path.join(WORKDIR, "jdk"))
                os.remove(jdk_tar)
            except Exception as e:
                log(f"[ERROR] فشل استخراج JDK: {e}")

    if not os.path.exists(os.path.join(WORKDIR, "paper.jar")):
        safe_download(
            "https://api.purpurmc.org/v2/purpur/1.21.1/latest/download",
            os.path.join(WORKDIR, "paper.jar"), "Purpur Server (1.21.1)")

    plugins_dir = os.path.join(WORKDIR, "plugins")
    os.makedirs(plugins_dir, exist_ok=True)

    if not os.path.exists(os.path.join(plugins_dir, "playit.jar")):
        safe_download(
            "https://github.com/playit-cloud/playit-minecraft-plugin/releases/latest/download/playit-minecraft-plugin.jar",
            os.path.join(plugins_dir, "playit.jar"), "Playit Plugin")

    if not os.path.exists(os.path.join(plugins_dir, "ViaVersion.jar")):
        via_url = "https://cdn.modrinth.com/data/P1OZGk5p/versions/ruzmiBqe/ViaVersion-5.10.0.jar?mr_download_reason=standalone&mr_game_version=1.21.1&mr_loader=paper"
        safe_download(via_url, os.path.join(plugins_dir, "ViaVersion.jar"), "ViaVersion Plugin")

    if not os.path.exists(os.path.join(plugins_dir, "ViaBackwards.jar")):
        via_b_url = "https://cdn.modrinth.com/data/NpvuJQoq/versions/YjpKsm6j/ViaBackwards-5.10.0.jar?mr_download_reason=standalone&mr_game_version=1.21.1&mr_loader=paper"
        safe_download(via_b_url, os.path.join(plugins_dir, "ViaBackwards.jar"), "ViaBackwards Plugin")

    if not os.path.exists(os.path.join(plugins_dir, "Geyser-Spigot.jar")):
        geyser_url = "https://cdn.modrinth.com/data/wKkoqHrH/versions/RHInMdHJ/Geyser-Spigot.jar?mr_download_reason=standalone&mr_game_version=1.21.1&mr_loader=paper"
        safe_download(geyser_url, os.path.join(plugins_dir, "Geyser-Spigot.jar"), "Geyser-Spigot Plugin (Bedrock support)")

    if not os.path.exists(os.path.join(plugins_dir, "floodgate.jar")):
        floodgate_url = "https://download.geysermc.org/v2/projects/floodgate/versions/latest/builds/latest/downloads/spigot"
        safe_download(floodgate_url, os.path.join(plugins_dir, "floodgate.jar"), "Floodgate Plugin (Bedrock accounts)")

    eula_p = os.path.join(WORKDIR, "eula.txt")
    if not os.path.exists(eula_p):
        with open(eula_p, "w") as f:
            f.write("eula=true\n")

    props_p = os.path.join(WORKDIR, "server.properties")
    if not os.path.exists(props_p):
        log("[SYSTEM] Configuring server.properties for cracked mode...")
        with open(props_p, "w") as f:
            f.write("online-mode=false\nspawn-protection=0\n")

def start_server_backend():
    global mc_process
    if mc_process and mc_process.poll() is None:
        log("[SYSTEM] Server is already running!")
        return

    download_dependencies()
    log("[SYSTEM] Starting Minecraft Server (Purpur 1.21.1)...")

    java_path = os.path.join(WORKDIR, "jdk/bin/java")
    mc_process = subprocess.Popen(
        [java_path, "-Xms2G", "-Xmx4G", "-jar", "paper.jar", "nogui"],
        cwd=WORKDIR, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )

    for line in iter(mc_process.stdout.readline, ''):
        if line:
            log(f"[MINECRAFT] {line.strip()}")

    mc_process.stdout.close()

def control_server(action, user):
    perm = action.lower()
    if not has_perm(user, perm):
        return f"⛔ You don't have `{perm}` permission"
    global mc_process
    if action == "START":
        if mc_process and mc_process.poll() is None:
            return "❌ السيرفر يعمل بالفعل الآن!"
        threading.Thread(target=start_server_backend, daemon=True).start()
        return "⚡ جاري تشغيل خادم ماين كرافت الآن..."
    elif action == "STOP":
        if mc_process and mc_process.poll() is None:
            try:
                mc_process.stdin.write("/stop\n")
                mc_process.stdin.flush()
                log("[SYSTEM] Sent /stop command — waiting for graceful shutdown...")
            except:
                pass
            deadline = time.time() + 8
            while time.time() < deadline:
                if mc_process.poll() is not None:
                    break
                time.sleep(0.5)
            if mc_process and mc_process.poll() is None:
                mc_process.terminate()
                time.sleep(1)
            mc_process = None
            log("[SYSTEM] Server stopped by user.")
            return "🛑 Server stopped gracefully."
        return "⚠️ Server is already stopped."
    elif action == "RESTART":
        if mc_process and mc_process.poll() is None:
            mc_process.terminate()
            mc_process = None
        log("[SYSTEM] Restarting server...")
        threading.Thread(target=start_server_backend, daemon=True).start()
        return "🔄 جاري إعادة تشغيل السيرفر..."

async def get_logs():
    return "\n".join(log_output)

async def get_server_status():
    status = "🟢 **Running**" if (mc_process and mc_process.poll() is None) else "🔴 **Stopped**"
    return f"## {status}\n\n**Purpur 1.21.1** — Java 21 — 2-4GB RAM"

# --- محرك إدارة الملفات المتقدم الحصري ---
def get_safe_path(rel_path):
    if rel_path is None:
        rel_path = ""
    rel_path = normalize_relative_path(rel_path)
    abs_path = os.path.realpath(os.path.join(WORKDIR, rel_path))
    if is_within_workdir(abs_path):
        return abs_path
    return os.path.realpath(WORKDIR)

async def scan_directory(current_rel):
    target_dir = get_safe_path(current_rel)
    folders = []
    text_files = []
    binary_count = 0
    try:
        entries = await asyncio.wait_for(
            asyncio.to_thread(lambda: list(os.listdir(target_dir))),
            timeout=5.0
        )
        for item in entries:
            full_path = os.path.join(target_dir, item)
            try:
                is_dir = await asyncio.to_thread(os.path.isdir, full_path)
                if is_dir:
                    folders.append(item)
                else:
                    ext = os.path.splitext(item)[1].lower()
                    if ext in BINARY_EXTENSIONS:
                        binary_count += 1
                    else:
                        text_files.append(item)
            except:
                text_files.append(item)
    except asyncio.TimeoutError:
        log(f"[FILE MGR ERROR] Timeout reading large directory")
        return "⚠️ المجلد كبير جداً ولا يمكن عرضه", gr.Dropdown(choices=["(مجلد ضخم)"], value=None), gr.Dropdown(choices=["(غير قابل للعرض)"], value=None)
    except Exception as e:
        log(f"[FILE MGR ERROR] {e}")

    folders.sort()
    text_files.sort()

    folder_choices = [".. (المجلد الأعلى)"] + folders if current_rel else folders
    file_choices = text_files if text_files else ["لا توجد ملفات نصية في هذا المسار"]

    path_display = f"📁 المسار الحالي المفتوح: /root/{current_rel}" if current_rel else "📁 المسار الحالي المفتوح: /root (المجلد الرئيسي)"
    if binary_count > 0:
        path_display += f"  \n📎 {binary_count} ملف ثنائي مخفي (jar/zip/png...) - استخدم الرفع لاستبدالها"

    return path_display, gr.Dropdown(choices=folder_choices, value=None), gr.Dropdown(choices=file_choices, value=None)

async def enter_folder(selected_folder, current_rel):
    if not selected_folder:
        return current_rel, *await scan_directory(current_rel)

    if selected_folder == ".. (المجلد الأعلى)":
        if not current_rel:
            return "", *await scan_directory("")
        parts = current_rel.strip("/").split("/")
        parent_rel = "/".join(parts[:-1])
        return parent_rel, *await scan_directory(parent_rel)
    else:
        new_rel = os.path.join(current_rel, selected_folder).strip("/")
        return new_rel, *await scan_directory(new_rel)


# امتدادات ثنائية معروفة يمنع فتحها كنص إطلاقاً (تتسبب بتجمد الصفحة)
BINARY_EXTENSIONS = {
    ".jar", ".zip", ".gz", ".tar", ".rar", ".7z", ".class",
    ".dat", ".mca", ".mcr", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".exe", ".bin", ".db", ".so", ".dll"
}

# الحد الأقصى لحجم الملف المسموح بفتحه في المحرر (بالبايت) - 200 كيلوبايت
MAX_EDITABLE_SIZE = 200 * 1024
PAGE_SIZE = 200

def is_probably_binary(file_path, chunk_size=1024):
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(chunk_size)
        return b"\x00" in chunk
    except Exception:
        return True

async def load_file_content(selected_file, current_rel):
    empty = gr.update(value="")
    title_reset = gr.update(value="### 📝 تعديل الملف: —")

    if not selected_file or "لا توجد ملفات" in selected_file:
        return empty, title_reset, gr.update(visible=False), gr.update(
            visible=True, value="👈 اختر ملفاً نصياً من القائمة على اليسار ليظهر صندوق التعديل هنا تلقائياً."), "", 0, gr.update(visible=False)

    try:
        file_path = resolve_safe_child_path(current_rel, selected_file)
    except ValueError as e:
        return empty, title_reset, gr.update(visible=False), gr.update(
            visible=True, value=f"⚠️ {e}"), "", 0, gr.update(visible=False)

    if not os.path.isfile(file_path):
        return empty, title_reset, gr.update(visible=False), gr.update(
            visible=True, value=f"⚠️ لا يمكن فتح [{selected_file}] لأنه مجلد وليس ملفاً."), "", 0, gr.update(visible=False)

    ext = os.path.splitext(selected_file)[1].lower()

    if ext in BINARY_EXTENSIONS:
        return empty, title_reset, gr.update(visible=False), gr.update(
            visible=True,
            value=f"🚫 لا يمكن عرض [{selected_file}] في المحرر لأنه ملف ثنائي (Binary) وليس ملف نصي.\n\n"
                  f"هذا النوع من الملفات (jar/zip/png/mca...) لا يُعدّل كنص، بل يُرفع أو يُستبدل فقط عبر خانة الرفع."), "", 0, gr.update(visible=False)

    try:
        size = await asyncio.to_thread(os.path.getsize, file_path)
    except Exception as e:
        return empty, title_reset, gr.update(visible=False), gr.update(
            visible=True, value=f"خطأ أثناء قراءة حجم الملف: {e}"), "", 0, gr.update(visible=False)

    if size > MAX_EDITABLE_SIZE:
        return empty, title_reset, gr.update(visible=False), gr.update(
            visible=True,
            value=f"🚫 الملف [{selected_file}] حجمه كبير جداً ({size/1024/1024:.2f} MB) وفتحه سيجمّد الصفحة.\n\n"
                  f"الحد المسموح للتحرير هو 200 كيلوبايت. استخدم زر الرفع لتبديله بدلاً من فتحه هنا."), "", 0, gr.update(visible=False)

    is_bin = await asyncio.to_thread(is_probably_binary, file_path)
    if is_bin:
        return empty, title_reset, gr.update(visible=False), gr.update(
            visible=True, value=f"🚫 الملف [{selected_file}] يحتوي على بيانات ثنائية غير قابلة للعرض كنص."), "", 0, gr.update(visible=False)

    try:
        content = await asyncio.to_thread(
            lambda: open(file_path, "r", encoding="utf-8", errors="ignore").read()
        )
        lines = content.splitlines(keepends=True)
        total_lines = len(lines)
        display_lines = lines[:PAGE_SIZE]
        has_more = total_lines > PAGE_SIZE
        display_content = "".join(display_lines)
        
        info = f"### 📝 تعديل الملف: `{selected_file}`"
        if has_more:
            info += f" — (عرض أول {PAGE_SIZE} من {total_lines} سطر)"
        
        lang_map = {".yml": "yaml", ".yaml": "yaml", ".json": "json",
                    ".properties": "yaml", ".txt": None, ".log": None}
        
        return (
            gr.update(value=display_content, language=lang_map.get(ext, None)),
            gr.update(value=info),
            gr.update(visible=True),
            gr.update(visible=False),
            file_path,
            PAGE_SIZE,
            gr.update(visible=has_more),
        )
    except Exception as e:
        return empty, title_reset, gr.update(visible=False), gr.update(
            visible=True, value=f"خطأ أثناء قراءة الملف: {e}"), "", 0, gr.update(visible=False)

async def load_more_content(file_path, load_offset):
    if not file_path or not os.path.isfile(file_path) or not is_within_workdir(file_path):
        return gr.update(), 0, gr.update(visible=False)
    
    content = await asyncio.to_thread(
        lambda: open(file_path, "r", encoding="utf-8", errors="ignore").read()
    )
    lines = content.splitlines(keepends=True)
    total = len(lines)
    new_offset = min(load_offset + PAGE_SIZE, total)
    full_text = "".join(lines[:new_offset])
    has_more = new_offset < total
    
    return gr.update(value=full_text), new_offset, gr.update(visible=has_more)

async def close_editor():
    return gr.update(visible=False), gr.update(
        visible=True, value=PLACEHOLDER_HTML)

async def save_file_content(selected_file, content, current_rel, user):
    if not has_perm(user, "files_write"):
        return "⛔ You don't have `files_write` permission"
    if not selected_file or "لا توجد ملفات" in selected_file:
        return "❌ لم يتم تحديد ملف صالح لحفظه."
    try:
        file_path = resolve_safe_child_path(current_rel, selected_file)
    except ValueError as e:
        return f"⚠️ {e}"
    try:
        await asyncio.to_thread(
            lambda: open(file_path, "w", encoding="utf-8").write(content)
        )
        return f"✅ تم حفظ الملف [{selected_file}] بنجاح في المسار الحالي!"
    except Exception as e:
        return f"❌ فشل الحفظ: {e}"

async def create_item(name, item_type, current_rel, user):
    if not has_perm(user, "files_write"):
        return "⛔ You don't have `files_write` permission", *await scan_directory(current_rel)
    if not name:
        return "⚠️ الرجاء إدخال اسم المجلد أو الملف أولاً.", *await scan_directory(current_rel)
    try:
        target_path = resolve_safe_child_path(current_rel, name)
    except ValueError as e:
        return f"⚠️ {e}", *await scan_directory(current_rel)
    try:
        if "Folder" in item_type or "مجلد" in item_type:
            await asyncio.to_thread(os.makedirs, target_path, exist_ok=True)
            msg = f"📁 Created folder [{name}]"
        else:
            await asyncio.to_thread(
                lambda: open(target_path, "w", encoding="utf-8").write("")
            )
            msg = f"📄 Created file [{name}]"
        return msg, *await scan_directory(current_rel)
    except Exception as e:
        return f"❌ فشل الإنشاء: {e}", *await scan_directory(current_rel)

async def rename_item(old_name, new_name, current_rel, user):
    if not has_perm(user, "files_write"):
        return "⛔ You don't have `files_write` permission", *await scan_directory(current_rel)
    if not old_name or not new_name:
        return "⚠️ حدد العنصر واكتب الاسم الجديد.", *await scan_directory(current_rel)
    try:
        old_p = resolve_safe_child_path(current_rel, old_name)
        new_p = resolve_safe_child_path(current_rel, new_name)
    except ValueError as e:
        return f"⚠️ {e}", *await scan_directory(current_rel)
    try:
        await asyncio.to_thread(os.rename, old_p, new_p)
        return f"✏️ تم إعادة التسمية بنجاح إلى [{new_name}].", *await scan_directory(current_rel)
    except Exception as e:
        return f"❌ خطأ أثناء التسمية: {e}", *await scan_directory(current_rel)

async def delete_item(item_name, is_folder, current_rel, user):
    if not has_perm(user, "files_delete"):
        return "⛔ You don't have `files_delete` permission", *await scan_directory(current_rel)
    if not item_name or "لا توجد ملفات" in item_name:
        return "⚠️ لم يتم تحديد عنصر لحذفه.", *await scan_directory(current_rel)
    try:
        target_p = resolve_safe_child_path(current_rel, item_name)
    except ValueError as e:
        return f"⚠️ {e}", *await scan_directory(current_rel)
    try:
        if is_folder:
            await asyncio.to_thread(shutil.rmtree, target_p)
            msg = f"🗑️ تم حذف المجلد ومحتوياته [{item_name}] بالكامل."
        else:
            await asyncio.to_thread(os.remove, target_p)
            msg = f"🗑️ تم حذف الملف [{item_name}]."
        return msg, *await scan_directory(current_rel)
    except Exception as e:
        return f"❌ فشل الحذف: {e}", *await scan_directory(current_rel)

async def upload_to_current_dir(file_objs, current_rel, user):
    if not has_perm(user, "files_write"):
        return "⛔ You don't have `files_write` permission", *await scan_directory(current_rel)
    if not file_objs:
        return "❌ لم يتم اختيار ملفات للرفع.", *await scan_directory(current_rel)
    target_dir = get_safe_path(current_rel)
    uploaded_list = []
    if not isinstance(file_objs, list):
        file_objs = [file_objs]
    for f_obj in file_objs:
        try:
            original_name = sanitize_upload_name(
                getattr(f_obj, 'orig_name', os.path.basename(f_obj.name))
            )
        except ValueError as e:
            return f"⚠️ {e}", *await scan_directory(current_rel)
        dest = os.path.join(target_dir, original_name)
        if not is_within_workdir(dest):
            return "⚠️ مسار الرفع خارج WORKDIR!", *await scan_directory(current_rel)
        await asyncio.to_thread(shutil.copy, f_obj.name, dest)
        uploaded_list.append(original_name)
    return f"✅ تم رفع {len(uploaded_list)} ملفات مباشرة إلى الدليل الحالي ومستعدة للاستخدام!", *await scan_directory(current_rel)

# ────────────────────────────────────────────────────────────
# CUSTOM HTML DASHBOARD — Pterodactyl/Atom Style
# ────────────────────────────────────────────────────────────

PLACEHOLDER_HTML = """<div style="display:none"></div>"""

DASHBOARD_HTML = r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
*{font-family:'Inter',sans-serif;box-sizing:border-box;margin:0;padding:0}
:root{
  color-scheme:dark;
  --bg-primary:#0a0a0f;
  --bg-secondary:#12121a;
  --bg-card:#181825;
  --bg-hover:#1e1e30;
  --bg-deep:#080810;
  --bg-input:#0d0d18;
  --border:#2a2a3e;
  --border-focus:rgba(68,189,50,0.4);
  --text-primary:#e8e8f0;
  --text-secondary:#8888a0;
  --text-muted:#5a5a72;
  --mc-green:#44bd32;
  --mc-red:#e74c3c;
  --mc-gold:#e1b12c;
  --mc-blue:#3498db;
  --mc-orange:#e67e22;
  --glow-green:0 0 20px rgba(68,189,50,0.15);
  --shadow-sm:0 2px 8px rgba(0,0,0,0.3);
  --shadow-md:0 4px 16px rgba(0,0,0,0.35);
  --shadow-lg:0 8px 32px rgba(0,0,0,0.45);
  --radius-sm:6px;
  --radius-md:10px;
  --radius-lg:12px;
}
::selection{background:rgba(68,189,50,0.3);color:#fff}
body{background:var(--bg-primary);color:var(--text-primary);overflow:hidden;height:100vh}

/* TOPBAR */
.topbar{
  height:56px;background:var(--bg-secondary);border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;padding:0 24px;
  flex-shrink:0;
}
.topbar-left{display:flex;align-items:center;gap:12px}
.topbar-logo{font-size:22px;font-weight:800;background:linear-gradient(135deg,#44bd32,#e1b12c);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.topbar-subtitle{font-size:12px;color:var(--text-muted);font-weight:400}
.topbar-right{display:flex;align-items:center;gap:14px}
.status-badge{
  display:inline-flex;align-items:center;gap:6px;
  padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600;
}
.status-badge.running{background:rgba(68,189,50,0.12);border:1px solid rgba(68,189,50,0.25);color:var(--mc-green)}
.status-badge.stopped{background:rgba(231,76,60,0.12);border:1px solid rgba(231,76,60,0.25);color:var(--mc-red)}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.status-dot.running{background:var(--mc-green);animation:pulse 2s infinite}
.status-dot.stopped{background:var(--mc-red)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.version-tag{font-size:11px;color:var(--text-muted)}

/* LAYOUT */
.layout{display:flex;height:calc(100vh - 56px)}
.sidebar{
  width:220px;min-width:220px;background:linear-gradient(180deg,var(--bg-secondary),var(--bg-primary));
  border-right:1px solid var(--border);padding:16px 10px;display:flex;flex-direction:column;gap:4px;overflow-y:auto;
}
.sidebar-label{
  font-size:10px;color:var(--text-muted);letter-spacing:2px;padding:8px 14px 10px;font-weight:600;text-transform:uppercase;
}
.sidebar-tab{
  display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;
  font-size:14px;font-weight:500;color:var(--text-secondary);cursor:pointer;
  transition:all 0.2s;border:none;background:transparent;width:100%;text-align:left;
}
.sidebar-tab:hover{background:var(--bg-hover);color:var(--text-primary)}
.sidebar-tab.active{
  background:rgba(68,189,50,0.08);color:var(--mc-green);
  border:1px solid rgba(68,189,50,0.15);box-shadow:var(--glow-green);
}
.main-content{flex:1;padding:20px 24px;overflow-y:auto;background:var(--bg-primary)}

/* TAB CONTENT */
.tab-content{display:none}
.tab-content.active{display:block}
.tab-title{font-size:22px;font-weight:700;margin-bottom:6px}
.tab-desc{color:var(--text-secondary);font-size:13px;margin-bottom:20px}

/* STAT CARDS */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.stat-card{
  background:var(--bg-card);border:1px solid var(--border);border-radius:12px;
  padding:16px 20px;transition:all 0.25s;position:relative;overflow:hidden;
}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--mc-green),transparent);opacity:0;transition:opacity 0.3s}
.stat-card:hover{border-color:rgba(68,189,50,0.25);box-shadow:var(--glow-green);transform:translateY(-2px)}
.stat-card:hover::before{opacity:1}
.stat-icon{font-size:20px;margin-bottom:6px}
.stat-label{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px}
.stat-value{font-size:28px;font-weight:700;color:var(--text-primary);margin-top:4px}
.stat-sub{font-size:12px;color:var(--text-secondary);margin-top:2px}
.stat-bar{display:inline-block;height:4px;background:var(--border);border-radius:2px;vertical-align:middle;margin-right:6px;overflow:hidden}
.stat-bar-fill{display:block;height:100%;background:var(--mc-green);border-radius:2px;transition:width 0.5s}

/* CONSOLE */
.console-wrap{
  background:var(--bg-deep);border:1px solid var(--border);border-radius:12px;overflow:hidden;
  transition:border-color 0.3s,box-shadow 0.3s;
}
.console-wrap:hover{border-color:rgba(68,189,50,0.3);box-shadow:0 0 30px rgba(68,189,50,0.06)}
.console-header{
  padding:10px 16px;background:var(--bg-input);border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
}
.console-dots{display:flex;gap:6px}
.console-dot{width:10px;height:10px;border-radius:50%;transition:opacity 0.3s}
.console-dot.red{background:#ff5f57}
.console-dot.yellow{background:#ffbd2e}
.console-dot.green{background:#28c840}
.console-title{font-size:12px;color:var(--text-muted)}
.console-live{font-size:11px;color:var(--mc-green);display:flex;align-items:center;gap:5px}
.live-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--mc-green);animation:live-pulse 1.5s infinite}
@keyframes live-pulse{0%,100%{opacity:1;box-shadow:0 0 4px var(--mc-green)}50%{opacity:0.4;box-shadow:none}}
.console-text{
  background:var(--bg-deep);color:#a0f0a0;font-family:'JetBrains Mono','Cascadia Code','Consolas',monospace;
  font-size:13px;line-height:1.6;padding:16px;min-height:320px;max-height:400px;
  overflow-y:auto;white-space:pre-wrap;word-break:break-word;
}
.console-text:empty::before{content:'[SYSTEM] Loading...';color:var(--text-muted)}

/* CONSOLE BUTTONS */
.console-actions{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:10px 22px;border-radius:10px;font-size:14px;font-weight:600;
  border:none;cursor:pointer;transition:all 0.25s;position:relative;overflow:hidden;
  white-space:nowrap;
}
.btn:hover{transform:translateY(-2px)}
.btn:active{transform:translateY(0)}
.btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,0.1),transparent);opacity:0;transition:opacity 0.3s}
.btn:hover::after{opacity:1}
.btn-primary{
  background:linear-gradient(135deg,#44bd32,#2ecc71,#3aa82a);background-size:200% 200%;
  color:#fff;box-shadow:0 4px 14px rgba(68,189,50,0.25);
}
.btn-primary:hover{background-position:100% 100%;box-shadow:0 6px 24px rgba(68,189,50,0.4)}
.btn-stop{
  background:linear-gradient(135deg,#e74c3c,#ff6b6b,#c0392b);background-size:200% 200%;
  color:#fff;box-shadow:0 4px 14px rgba(231,76,60,0.25);
}
.btn-stop:hover{background-position:100% 100%;box-shadow:0 6px 24px rgba(231,76,60,0.4)}
.btn-secondary{
  background:var(--bg-card);border:1px solid var(--border);color:var(--text-primary);
}
.btn-secondary:hover{border-color:var(--mc-green);background:var(--bg-hover);box-shadow:0 4px 16px rgba(68,189,50,0.1)}
.btn-sm{padding:8px 16px;font-size:13px}
.btn:disabled{opacity:0.5;cursor:not-allowed;transform:none}

/* FILE MANAGER */
.path-bar{
  display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg-card);
  border:1px solid var(--border);border-radius:10px;margin-bottom:16px;
  font-size:13px;overflow-x:auto;white-space:nowrap;
}
.path-icon{font-size:16px}
.path-label{color:var(--text-secondary);font-weight:500}
.path-value{color:var(--mc-green);font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600}
.file-layout{display:grid;grid-template-columns:280px 1fr;gap:16px;min-height:400px}
.file-sidebar{display:flex;flex-direction:column;gap:12px}
.file-section{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.file-section-header{padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;display:flex;align-items:center;gap:8px}
.file-list{padding:6px;max-height:200px;overflow-y:auto}
.file-item{
  display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:6px;
  cursor:pointer;font-size:13px;color:var(--text-secondary);transition:all 0.15s;
}
.file-item:hover{background:var(--bg-hover);color:var(--text-primary)}
.file-item.active{background:rgba(68,189,50,0.1);color:var(--mc-green)}
.file-item.folder{color:var(--mc-gold)}
.file-item .icon{font-size:14px;flex-shrink:0}
.file-editor-panel{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;overflow:hidden;display:flex;flex-direction:column}
.file-editor-header{padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:600;color:var(--text-secondary);display:flex;align-items:center;justify-content:space-between}
.file-editor-header .fname{color:var(--text-primary);font-family:'JetBrains Mono',monospace;font-size:13px}
.editor-textarea{
  width:100%;min-height:360px;padding:14px;background:var(--bg-deep);color:#a0f0a0;
  font-family:'JetBrains Mono','Cascadia Code','Consolas',monospace;font-size:13px;line-height:1.6;
  border:none;resize:vertical;outline:none;tab-size:2;
}
.editor-textarea:focus{background:var(--bg-primary);box-shadow:inset 0 0 0 1px var(--border-focus)}
.editor-actions{display:flex;gap:8px;padding:10px 14px;border-top:1px solid var(--border);flex-wrap:wrap}
.editor-placeholder{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:80px 20px;text-align:center;color:var(--text-secondary);
}
.editor-placeholder .big-icon{font-size:48px;margin-bottom:16px;opacity:0.5}
.editor-placeholder .text{font-size:15px;font-weight:500}
.editor-placeholder .sub{font-size:13px;color:var(--text-muted);margin-top:6px}

/* FILE OPERATIONS */
.file-ops-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:16px}
.file-op-section{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.file-op-header{padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;display:flex;align-items:center;gap:8px}
.file-op-body{padding:12px 14px;display:flex;flex-direction:column;gap:8px}
.file-op-body input,.file-op-body select{
  background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);
  padding:8px 12px;font-size:13px;outline:none;width:100%;
}
.file-op-body input:focus{border-color:var(--mc-green);box-shadow:0 0 0 3px rgba(68,189,50,0.1)}
.file-op-body .op-row{display:flex;gap:8px;align-items:center}
.file-op-body .op-row .btn{flex-shrink:0}
.op-status{padding:8px 14px;font-size:13px;color:var(--text-secondary);min-height:20px}

/* USERS PANEL */
.users-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}
.users-section{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.users-section-header{padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;display:flex;align-items:center;gap:8px}
.users-section-body{padding:12px 14px;display:flex;flex-direction:column;gap:8px}
.users-section-body input{background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);padding:8px 12px;font-size:13px;outline:none;width:100%}
.users-section-body input:focus{border-color:var(--mc-green);box-shadow:0 0 0 3px rgba(68,189,50,0.1)}
.users-list{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:14px}
.users-list .markdown{font-size:14px;line-height:1.8;color:var(--text-secondary)}
.user-action-msg{padding:8px 0;font-size:13px;color:var(--text-secondary);min-height:20px}

/* CONSOLE COMMAND INPUT */
.console-cmd-wrap{display:flex;gap:8px;margin-top:10px;align-items:center}
.console-cmd-input{flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--mc-green);padding:10px 14px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:13px;outline:none;transition:border-color 0.3s,box-shadow 0.3s}
.console-cmd-input:focus{border-color:var(--mc-green);box-shadow:0 0 0 3px rgba(68,189,50,0.15)}
.console-cmd-input::placeholder{color:var(--text-muted)}

/* TOAST NOTIFICATIONS */
.toast-container{position:fixed;top:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:10px;pointer-events:none}
.toast{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:12px 18px;font-size:13px;color:var(--text-primary);box-shadow:0 8px 32px rgba(0,0,0,0.4);transform:translateX(120%);transition:transform 0.4s cubic-bezier(0.22,1,0.36,1),opacity 0.3s;pointer-events:auto;max-width:380px;display:flex;align-items:center;gap:10px}
.toast.show{transform:translateX(0)}
.toast.hide{opacity:0;transform:translateX(120%)}
.toast.success{border-left:3px solid var(--mc-green)}
.toast.error{border-left:3px solid var(--mc-red)}
.toast.info{border-left:3px solid var(--mc-blue)}
.toast-icon{font-size:16px;flex-shrink:0}

/* SETTINGS PANEL */
.settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.settings-group{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.settings-group-header{padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;display:flex;align-items:center;gap:8px}
.settings-group-body{padding:12px 14px;display:flex;flex-direction:column;gap:10px}
.settings-row{display:flex;align-items:center;justify-content:space-between;gap:12px}
.settings-row label{font-size:13px;color:var(--text-secondary);flex:1}
.settings-row input,.settings-row select{background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);padding:7px 10px;font-size:13px;outline:none;flex:1;max-width:200px}
.settings-row input:focus,.settings-row select:focus{border-color:var(--mc-green);box-shadow:0 0 0 3px rgba(68,189,50,0.1)}
.toggle-switch{position:relative;width:40px;height:22px;flex-shrink:0}
.toggle-switch input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;cursor:pointer;inset:0;background:var(--border);border-radius:22px;transition:background 0.3s}
.toggle-slider::before{content:'';position:absolute;width:16px;height:16px;left:3px;bottom:3px;background:var(--text-muted);border-radius:50%;transition:transform 0.3s,background 0.3s}
.toggle-switch input:checked + .toggle-slider{background:var(--mc-green)}
.toggle-switch input:checked + .toggle-slider::before{transform:translateX(18px);background:#fff}

/* FILE DOWNLOAD BUTTON */
.dl-btn{background:none;border:none;color:var(--text-secondary);cursor:pointer;font-size:13px;padding:4px 8px;border-radius:4px;transition:color 0.2s,background 0.2s}
.dl-btn:hover{color:var(--mc-green);background:rgba(68,189,50,0.1)}

@media(max-width:1024px){
  .stat-grid{grid-template-columns:repeat(2,1fr)}
  .main-content{padding:16px 18px}
}
@media(max-width:768px){
  .settings-grid{grid-template-columns:1fr}
}

/* SCROLLBAR */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--text-muted)}

/* FOCUS-VISIBLE — accessibility */
.btn:focus-visible,
.sidebar-tab:focus-visible,
.toggle-slider:focus-visible{
  outline:2px solid var(--mc-green);
  outline-offset:2px;
  box-shadow:0 0 0 4px rgba(68,189,50,0.2);
}
.console-cmd-input:focus-visible,
.editor-textarea:focus-visible,
.file-op-body input:focus-visible,
.file-op-body select:focus-visible,
.users-section-body input:focus-visible,
.settings-row input:focus-visible,
.settings-row select:focus-visible{
  border-color:var(--border-focus);
  box-shadow:0 0 0 3px rgba(68,189,50,0.15);
}

/* SIDEBAR active indicator bar */
.sidebar-tab{position:relative;border-left:3px solid transparent;padding-left:11px}
.sidebar-tab.active{border-left-color:var(--mc-green)}

/* TAB TRANSITION ANIMATION */
.tab-content.active{animation:tabFadeIn 0.25s ease-out}
@keyframes tabFadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

/* BUTTON RIPPLE EFFECT */
.btn{position:relative;overflow:hidden}
.btn::before{
  content:'';position:absolute;top:50%;left:50%;width:0;height:0;
  background:radial-gradient(circle,rgba(255,255,255,0.25),transparent 70%);
  border-radius:50%;transform:translate(-50%,-50%);transition:width 0.4s,opacity 0.4s;opacity:0;
}
.btn:active::before{width:300px;height:300px;opacity:1;transition:0s}

/* BUTTON LOADING STATE */
.btn.loading{pointer-events:none;opacity:0.7}
.btn.loading::after{display:none}
.btn.loading::before{
  content:'';width:16px;height:16px;border:2px solid rgba(255,255,255,0.3);
  border-top-color:#fff;border-radius:50%;animation:spin 0.6s linear infinite;
  position:static;transform:none;opacity:1;flex-shrink:0;
}
@keyframes spin{to{transform:rotate(360deg)}}

/* FILE ITEM KEYBOARD FOCUS */
.file-item:focus-visible{
  outline:2px solid var(--mc-green);outline-offset:1px;
  background:var(--bg-hover);
}

/* FILE ITEM ENTRANCE ANIMATION */
.file-item{animation:itemFadeIn 0.2s ease-out both}
@keyframes itemFadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}

/* CONSOLE NEW LINE ANIMATION */
.console-text .con-new{animation:conLineFade 0.15s ease-out}
@keyframes conLineFade{from{opacity:0}to{opacity:1}}

/* EMPTY STATE IMPROVEMENTS */
.empty-state{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:32px 16px;text-align:center;color:var(--text-muted);
}
.empty-state .empty-icon{font-size:32px;margin-bottom:8px;opacity:0.4}
.empty-state .empty-text{font-size:13px}

/* MODAL OVERLAY */
.modal-overlay{
  position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);
  display:none;align-items:center;justify-content:center;z-index:100000;
}
.modal-overlay.show{display:flex}
.modal-box{
  background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);
  padding:24px;max-width:400px;width:90%;box-shadow:var(--shadow-lg);
  animation:modalIn 0.2s ease-out;
}
@keyframes modalIn{from{opacity:0;transform:scale(0.95)}to{opacity:1;transform:scale(1)}}
.modal-title{font-size:16px;font-weight:700;margin-bottom:8px}
.modal-msg{font-size:13px;color:var(--text-secondary);margin-bottom:20px;line-height:1.5}
.modal-actions{display:flex;gap:10px;justify-content:flex-end}

/* DRAG-AND-DROP ZONE */
.drop-zone{
  border:2px dashed var(--border);border-radius:var(--radius-md);padding:24px;
  text-align:center;color:var(--text-muted);font-size:13px;transition:all 0.3s;
  margin-bottom:12px;cursor:pointer;
}
.drop-zone.dragover{
  border-color:var(--mc-green);background:rgba(68,189,50,0.05);
  color:var(--mc-green);
}
.drop-zone .drop-icon{font-size:28px;margin-bottom:6px;opacity:0.5}

/* CONSOLE WORD WRAP TOGGLE */
.console-wrap.nowrap .console-text{white-space:pre;word-break:normal}

/* GLASSMORPHISM TOPBAR */
.topbar{backdrop-filter:blur(12px);background:rgba(18,18,26,0.85)}

/* CONSOLE HEADER GLASSMORPHISM */
.console-header{backdrop-filter:blur(8px)}

/* PATH BAR CLICKABLE SEGMENTS */
.path-segment{cursor:pointer;color:var(--mc-green);transition:color 0.2s}
.path-segment:hover{color:#5dd840;text-decoration:underline}

/* MAX-WIDTH CONTAINER */
.main-content{max-width:1400px;margin:0 auto}

/* RESPONSIVE — Mobile */
@media(max-width:768px){
  .sidebar{width:100%;min-width:100%;flex-direction:row;overflow-x:auto;padding:8px;border-right:none;border-bottom:1px solid var(--border)}
  .sidebar-label{display:none}
  .sidebar-tab{white-space:nowrap;padding:8px 12px;font-size:13px;border-left:none}
  .layout{flex-direction:column}
  .stat-grid{grid-template-columns:repeat(2,1fr);gap:10px}
  .stat-value{font-size:22px}
  .file-layout{grid-template-columns:1fr}
  .file-ops-grid{grid-template-columns:1fr}
  .users-grid{grid-template-columns:1fr}
  .topbar-subtitle{display:none}
  .topbar{padding:0 14px}
  .main-content{padding:12px}
  .editor-textarea{min-height:240px}
  .file-item{padding:10px 12px}
  .console-text{min-height:240px;max-height:300px}
  .console-wrap{touch-action:manipulation}
  .modal-box{max-width:95vw;padding:18px}
}
</style>

<!-- TOAST CONTAINER -->
<div class="toast-container" id="toast-container" role="alert" aria-live="polite"></div>

<!-- CONFIRMATION MODAL -->
<div class="modal-overlay" id="modal-overlay">
  <div class="modal-box">
    <div class="modal-title" id="modal-title">Are you sure?</div>
    <div class="modal-msg" id="modal-msg">This action cannot be undone.</div>
    <div class="modal-actions">
      <button class="btn btn-secondary btn-sm" onclick="modalClose()">Cancel</button>
      <button class="btn btn-stop btn-sm" id="modal-confirm" onclick="modalConfirm()">Confirm</button>
    </div>
  </div>
</div>

<!-- TOPBAR -->
<div class="topbar">
  <div class="topbar-left">
    <span class="topbar-logo">⛏️ MC Server</span>
    <span class="topbar-subtitle">Control Panel</span>
  </div>
  <div class="topbar-right">
    <div class="status-badge running" id="status-badge">
      <span class="status-dot running" id="status-dot"></span>
      <span id="status-text">Running</span>
    </div>
    <span class="version-tag">Purpur 1.21.1</span>
  </div>
</div>

<!-- LAYOUT -->
<div class="layout">
  <!-- SIDEBAR -->
  <div class="sidebar" role="tablist" aria-label="Navigation">
    <div class="sidebar-label">Navigation</div>
    <button class="sidebar-tab active" data-tab="console" onclick="switchTab('console')" role="tab" aria-selected="true" aria-controls="tab-console">
      <span aria-hidden="true">🖥️</span> Console
    </button>
    <button class="sidebar-tab" data-tab="files" onclick="switchTab('files')" role="tab" aria-selected="false" aria-controls="tab-files">
      <span aria-hidden="true">📂</span> File Manager
    </button>
    <button class="sidebar-tab" data-tab="settings" onclick="switchTab('settings')" role="tab" aria-selected="false" aria-controls="tab-settings">
      <span aria-hidden="true">⚙️</span> Settings
    </button>
    <button class="sidebar-tab" data-tab="users" onclick="switchTab('users')" role="tab" aria-selected="false" aria-controls="tab-users">
      <span aria-hidden="true">👥</span> Users
    </button>
  </div>

  <!-- MAIN CONTENT -->
  <div class="main-content">

    <!-- TAB: CONSOLE -->
    <div class="tab-content active" id="tab-console" role="tabpanel" aria-labelledby="tab-console">
      <div class="tab-title">Console</div>
      <div class="tab-desc">Monitor and control your Minecraft server in real-time</div>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-icon">🧠</div>
          <div class="stat-label">Memory</div>
          <div class="stat-value" id="stat-memory">— / — GB</div>
          <div class="stat-sub"><span class="stat-bar" style="width:60px"><span class="stat-bar-fill" style="width:0%" id="stat-memory-bar"></span></span><span id="stat-memory-pct">0%</span></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">⚡</div>
          <div class="stat-label">CPU</div>
          <div class="stat-value" id="stat-cpu">—%</div>
          <div class="stat-sub" id="stat-cpu-sub">Waiting for data</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">👤</div>
          <div class="stat-label">Players</div>
          <div class="stat-value" id="stat-players">0</div>
          <div class="stat-sub" id="stat-players-list">No players online</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">⏱️</div>
          <div class="stat-label">Status</div>
          <div class="stat-value" id="stat-status">🔴 Stopped</div>
          <div class="stat-sub" id="stat-uptime">Uptime: —</div>
        </div>
      </div>

      <div class="console-wrap" id="console-wrap">
        <div class="console-header">
          <div class="console-dots">
            <span class="console-dot red"></span>
            <span class="console-dot yellow"></span>
            <span class="console-dot green"></span>
          </div>
          <span class="console-title">SERVER CONSOLE — live.log</span>
          <div style="display:flex;align-items:center;gap:12px">
            <button class="btn btn-secondary btn-sm" onclick="toggleWrap()" title="Toggle word wrap" style="padding:4px 8px;font-size:11px">↩️ Wrap</button>
            <span class="console-live"><span class="live-dot"></span> Live</span>
          </div>
        </div>
        <div class="console-text" id="console-text" role="log" aria-live="polite">[SYSTEM] Loading server system...</div>
      </div>

      <div class="console-actions">
        <button class="btn btn-primary" id="btn-start" onclick="bridgeClick('gb-start')">▶️ Start Server</button>
        <button class="btn btn-stop" id="btn-stop" onclick="confirmModal('Stop Server','Are you sure you want to stop the Minecraft server? Players will be disconnected.','Stop Server',function(){bridgeClick('gb-stop')})">🛑 Stop Server</button>
        <button class="btn btn-secondary" id="btn-restart" onclick="bridgeClick('gb-restart')">🔄 Restart</button>
        <button class="btn btn-secondary" id="btn-refresh-console" onclick="bridgeClick('gb-refresh-con')">🔄 Refresh</button>
      </div>
      <div class="console-cmd-wrap">
        <input class="console-cmd-input" id="console-cmd-input" type="text" placeholder="Type a command... (↑↓ for history)" onkeydown="if(event.key==='Enter')sendCmd();else handleCmdKey(event)">
        <button class="btn btn-primary" onclick="sendCmd()">▶ Send</button>
      </div>
      <div class="op-status" id="op-status-console"></div>
    </div>

    <!-- TAB: FILE MANAGER -->
    <div class="tab-content" id="tab-files" role="tabpanel" aria-labelledby="tab-files">
      <div class="tab-title">File Manager</div>
      <div class="tab-desc">Browse, edit, upload, and manage server files</div>

      <div class="path-bar">
        <span class="path-icon">📁</span>
        <span class="path-label">Path:</span>
        <span class="path-value" id="current-path">/root</span>
      </div>

      <div class="drop-zone" id="drop-zone" onclick="document.getElementById('upload-input').click()">
        <div class="drop-icon">📤</div>
        <div>Drag files here or <strong>click to browse</strong></div>
      </div>

      <div class="file-layout">
        <div class="file-sidebar">
          <div class="file-section">
            <div class="file-section-header"><span>📂</span> Folders</div>
            <div class="file-list" id="folder-list">
              <div class="file-item" style="color:var(--text-muted);font-size:12px;cursor:default">Loading...</div>
            </div>
          </div>
          <div class="file-section">
            <div class="file-section-header"><span>📄</span> Files</div>
            <div class="file-list" id="file-list">
              <div class="file-item" style="color:var(--text-muted);font-size:12px;cursor:default">Loading...</div>
            </div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="refreshDir()" style="width:100%">🔄 Refresh Directory</button>
        </div>

        <div class="file-editor-panel" id="editor-panel">
          <div class="file-editor-header">
            <span><span class="fname" id="editor-fname">Select a file</span></span>
            <span style="display:flex;gap:6px">
              <button class="btn btn-secondary btn-sm" onclick="downloadCurrentFile()">⬇️ Download</button>
              <button class="btn btn-secondary btn-sm" onclick="reloadFile()">📂 Reload</button>
              <button class="btn btn-primary btn-sm" onclick="saveFile()">💾 Save</button>
              <button class="btn btn-secondary btn-sm" id="btn-load-more" style="display:none" onclick="loadMore()">📄 Load More</button>
            </span>
          </div>
          <textarea class="editor-textarea" id="editor-content" placeholder="Select a file from the sidebar to start editing..." spellcheck="false"></textarea>
          <div class="editor-actions">
            <div class="op-status" id="op-status-files"></div>
          </div>
        </div>
      </div>

      <div class="file-ops-grid" style="margin-top:16px">
        <div class="file-op-section">
          <div class="file-op-header"><span>➕</span> Create</div>
          <div class="file-op-body">
            <input type="text" id="create-name" placeholder="example.yml" style="width:100%">
            <div class="op-row">
              <select id="create-type" style="flex:1">
                <option value="File">📄 File</option>
                <option value="Folder">📁 Folder</option>
              </select>
              <button class="btn btn-primary btn-sm" onclick="createItem()">➕ Create</button>
            </div>
          </div>
        </div>
        <div class="file-op-section">
          <div class="file-op-header"><span>✏️</span> Rename</div>
          <div class="file-op-body">
            <input type="text" id="rename-old" placeholder="Current name (click a file)">
            <div class="op-row">
              <input type="text" id="rename-new" placeholder="New name" style="flex:1">
              <button class="btn btn-secondary btn-sm" onclick="renameItem()">✏️ Apply</button>
            </div>
          </div>
        </div>
        <div class="file-op-section">
          <div class="file-op-header"><span>📤</span> Upload</div>
          <div class="file-op-body">
            <input type="file" id="upload-input" multiple style="display:none">
            <div class="op-row">
              <button class="btn btn-secondary btn-sm" onclick="document.getElementById('upload-input').click()">📁 Choose Files</button>
              <button class="btn btn-primary btn-sm" onclick="uploadFiles()">🚀 Upload</button>
            </div>
            <div style="font-size:12px;color:var(--text-muted)" id="upload-files-label">No files selected</div>
          </div>
        </div>
        <div class="file-op-section">
          <div class="file-op-header"><span>🗑️</span> Delete</div>
          <div class="file-op-body">
            <div class="op-row">
              <input type="text" id="delete-name" placeholder="Name to delete (click a file)" style="flex:1">
              <button class="btn btn-stop btn-sm" onclick="var n=document.getElementById('delete-name').value;if(!n)return;confirmModal('Delete "'+n+'"','This will permanently delete this file/folder. Are you sure?','Delete',function(){deleteItem()})">❌ Delete</button>
            </div>
            <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text-secondary);cursor:pointer">
              <input type="checkbox" id="delete-is-folder"> This is a folder
            </label>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB: SETTINGS -->
    <div class="tab-content" id="tab-settings" role="tabpanel" aria-labelledby="tab-settings">
      <div class="tab-title">Server Settings</div>
      <div class="tab-desc">Edit server.properties directly — restart server after changes</div>

      <div style="text-align:right;margin-bottom:12px">
        <button class="btn btn-primary btn-sm" onclick="loadSettings()">🔄 Reload from Disk</button>
        <button class="btn btn-primary btn-sm" onclick="saveSettings()">💾 Save Settings</button>
      </div>

      <div class="settings-grid">
        <div class="settings-group">
          <div class="settings-group-header"><span>🎮</span> Game Settings</div>
          <div class="settings-group-body">
            <div class="settings-row"><label>Difficulty</label><select id="s-difficulty"><option>peaceful</option><option>easy</option><option selected>normal</option><option>hard</option></select></div>
            <div class="settings-row"><label>Gamemode</label><select id="s-gamemode"><option>survival</option><option>creative</option><option>adventure</option><option>spectator</option></select></div>
            <div class="settings-row"><label>Max Players</label><input type="number" id="s-max-players" value="20" min="1" max="100"></div>
            <div class="settings-row"><label>View Distance</label><input type="number" id="s-view-distance" value="10" min="2" max="32"></div>
            <div class="settings-row"><label>Simulation Distance</label><input type="number" id="s-sim-distance" value="10" min="2" max="32"></div>
            <div class="settings-row"><label>Spawn Protection</label><input type="number" id="s-spawn-protection" value="0" min="0" max="100"></div>
            <div class="settings-row"><label>World Name</label><input type="text" id="s-level-name" value="world"></div>
            <div class="settings-row"><label>Seed</label><input type="text" id="s-seed" placeholder="(empty = random)"></div>
          </div>
        </div>
        <div class="settings-group">
          <div class="settings-group-header"><span>🔒</span> Network & Security</div>
          <div class="settings-group-body">
            <div class="settings-row"><label>Online Mode</label><label class="toggle-switch"><input type="checkbox" id="s-online-mode"><span class="toggle-slider"></span></label></div>
            <div class="settings-row"><label>PvP</label><label class="toggle-switch"><input type="checkbox" id="s-pvp" checked><span class="toggle-slider"></span></label></div>
            <div class="settings-row"><label>Allow Nether</label><label class="toggle-switch"><input type="checkbox" id="s-allow-nether" checked><span class="toggle-slider"></span></label></div>
            <div class="settings-row"><label>Spawn Monsters</label><label class="toggle-switch"><input type="checkbox" id="s-spawn-monsters" checked><span class="toggle-slider"></span></label></div>
            <div class="settings-row"><label>Spawn Animals</label><label class="toggle-switch"><input type="checkbox" id="s-spawn-animals" checked><span class="toggle-slider"></span></label></div>
            <div class="settings-row"><label>Force Gamemode</label><label class="toggle-switch"><input type="checkbox" id="s-force-gamemode"><span class="toggle-slider"></span></label></div>
            <div class="settings-row"><label>Whitelist</label><label class="toggle-switch"><input type="checkbox" id="s-whitelist"><span class="toggle-slider"></span></label></div>
            <div class="settings-row"><label>Enable Command Block</label><label class="toggle-switch"><input type="checkbox" id="s-cmd-block"><span class="toggle-slider"></span></label></div>
          </div>
        </div>
      </div>
      <div class="op-status" id="op-status-settings"></div>
    </div>

    <!-- TAB: USERS -->
    <div class="tab-content" id="tab-users" role="tabpanel" aria-labelledby="tab-users">
      <div class="tab-title">User Management</div>
      <div class="tab-desc">Add or remove collaborators and set their permissions</div>

      <div class="users-grid">
        <div class="users-section">
          <div class="users-section-header"><span>➕</span> Add / Update User</div>
          <div class="users-section-body">
            <input type="text" id="add-username" placeholder="Hugging Face Username">
            <select id="add-role" style="background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);padding:8px 12px;font-size:13px;outline:none;width:100%">
              <option value="editor">Editor</option>
              <option value="admin">Admin</option>
              <option value="viewer">Viewer</option>
            </select>
            <button class="btn btn-primary btn-sm" onclick="addUser()">➕ Add User</button>
          </div>
        </div>
        <div class="users-section">
          <div class="users-section-header"><span>🗑️</span> Remove User</div>
          <div class="users-section-body">
            <input type="text" id="remove-username" placeholder="Username to remove">
            <button class="btn btn-stop btn-sm" onclick="removeUser()">🗑️ Remove User</button>
          </div>
        </div>
      </div>

      <div class="users-list">
        <div class="users-section-header" style="border-bottom:none;padding:0 0 10px 0"><span>📋</span> Current Users</div>
        <div class="markdown" id="users-list">*No users configured yet*</div>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="refreshUsers()" style="margin-top:10px">🔄 Refresh List</button>
      <div class="user-action-msg" id="op-status-users"></div>
    </div>

  </div>
</div>
"""

DASHBOARD_JS = r"""
// ========== TAB SWITCHING ==========
function switchTab(name) {
  document.querySelectorAll('.sidebar-tab').forEach(t => {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
  });
  var activeTab = document.querySelector('.sidebar-tab[data-tab="' + name + '"]');
  if (activeTab) {
    activeTab.classList.add('active');
    activeTab.setAttribute('aria-selected', 'true');
  }
  document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
  var panel = document.getElementById('tab-' + name);
  if (panel) {
    panel.classList.add('active');
    // Move focus to panel for screen readers
    panel.setAttribute('tabindex', '-1');
    panel.focus({ preventScroll: true });
  }
  // Trigger data refresh on tab switch
  if (name === 'files') refreshDir();
  if (name === 'users') refreshUsers();
  if (name === 'settings') loadSettings();
}

// ========== GRADIO BRIDGE ==========
function gradioVal(id) {
  const root = document.getElementById(id);
  if (!root) return '';
  const ta = root.querySelector('textarea');
  if (ta) return ta.value;
  const inp = root.querySelector('input[type="text"], input:not([type])');
  if (inp) return inp.value;
  const sel = root.querySelector('select');
  if (sel) return sel.value;
  const div = root.querySelector('.markdown');
  if (div) return div.innerText;
  return '';
}

function setGradioVal(id, value) {
  const root = document.getElementById(id);
  if (!root) return;
  const el = root.querySelector('textarea') || root.querySelector('input');
  if (!el) return;
  const proto = el instanceof HTMLTextAreaElement ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
  setter.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}

function setGradioSelect(id, value) {
  const root = document.getElementById(id);
  if (!root) return;
  const sel = root.querySelector('select');
  if (!sel) return;
  sel.value = value;
  sel.dispatchEvent(new Event('change', { bubbles: true }));
}

function setGradioChecked(id, checked) {
  const root = document.getElementById(id);
  if (!root) return;
  const cb = root.querySelector('input[type="checkbox"]');
  if (!cb) return;
  cb.checked = checked;
  cb.dispatchEvent(new Event('change', { bubbles: true }));
}

function bridgeClick(id) {
  const root = document.getElementById(id);
  if (!root) return;
  const btn = root.querySelector('button') || root.querySelector('[role="button"]') || root;
  if (btn) {
    btn.click();
    btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
  }
}

// ========== CONSOLE ACTIONS ==========
function refreshConsole() { bridgeClick('gb-refresh-con'); }

// ========== FILE MANAGER ACTIONS ==========
var _selectedFile = '';
var _selectedFolder = '';

function refreshDir() { bridgeClick('gb-refresh-dir'); }

function clickFolder(name) {
  _selectedFolder = name;
  document.querySelectorAll('#folder-list .file-item').forEach(e => e.classList.remove('active'));
  const items = document.querySelectorAll('#folder-list .file-item');
  for (let item of items) {
    if (item.textContent.trim() === name) {
      item.classList.add('active');
      break;
    }
  }
  setGradioVal('gv-folder', name);
  bridgeClick('gb-enter-folder');
}

function clickFile(name) {
  _selectedFile = name;
  document.querySelectorAll('#file-list .file-item').forEach(e => e.classList.remove('active'));
  const items = document.querySelectorAll('#file-list .file-item');
  for (let item of items) {
    if (item.textContent.trim() === name) {
      item.classList.add('active');
      break;
    }
  }
  document.getElementById('rename-old').value = name;
  document.getElementById('delete-name').value = name;
  setGradioVal('gv-file', name);
  bridgeClick('gb-select-file');
}

function reloadFile() {
  if (_selectedFile) {
    setGradioVal('gv-file', _selectedFile);
    bridgeClick('gb-select-file');
  }
}

function saveFile() {
  var btn = document.querySelector('#editor-panel .btn-primary');
  if (btn) { btn.dataset.origText = btn.textContent; btn.textContent = '💾 Saving...'; btn.disabled = true; }
  const content = document.getElementById('editor-content').value;
  setGradioVal('gv-content', content);
  bridgeClick('gb-save-file');
  setTimeout(function() { if (btn) { btn.textContent = btn.dataset.origText || '💾 Save'; btn.disabled = false; } }, 1200);
}

function loadMore() {
  const content = document.getElementById('editor-content').value;
  setGradioVal('gv-content', content);
  bridgeClick('gb-load-more');
}

function createItem() {
  const name = document.getElementById('create-name').value;
  const type = document.getElementById('create-type').value;
  if (!name) return;
  setGradioVal('gv-name', name);
  setGradioVal('gv-type', type === 'Folder' ? 'Folder' : 'File');
  bridgeClick('gb-create');
  document.getElementById('create-name').value = '';
}

function renameItem() {
  const old = document.getElementById('rename-old').value;
  const name = document.getElementById('rename-new').value;
  if (!old || !name) return;
  setGradioVal('gv-old', old);
  setGradioVal('gv-name', name);
  bridgeClick('gb-rename');
  document.getElementById('rename-new').value = '';
}

function deleteItem() {
  const name = document.getElementById('delete-name').value;
  const isFolder = document.getElementById('delete-is-folder').checked;
  if (!name) return;
  setGradioVal('gv-old', name);
  setGradioChecked('gv-del-folder', isFolder);
  bridgeClick('gb-delete');
  document.getElementById('delete-name').value = '';
  _selectedFile = '';
  document.querySelectorAll('#file-list .file-item').forEach(e => e.classList.remove('active'));
}

function uploadFiles() {
  const input = document.getElementById('upload-input');
  if (!input.files.length) return;
  const dt = new DataTransfer();
  for (let f of input.files) dt.items.add(f);
  const fileList = dt.files;
  const hidden = document.querySelector('#gv-upload input[type="file"]');
  if (hidden) {
    const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'files').set;
    proto.call(hidden, fileList);
    hidden.dispatchEvent(new Event('change', { bubbles: true }));
  }
  document.getElementById('upload-files-label').textContent = 'Uploading...';
  bridgeClick('gb-upload');
  input.value = '';
  setTimeout(function() { document.getElementById('upload-files-label').textContent = 'No files selected'; }, 2000);
}

function bindUploadInput() {
  var up = document.getElementById('upload-input');
  if (up) up.addEventListener('change', function() {
    var lbl = document.getElementById('upload-files-label');
    if (lbl) lbl.textContent = this.files.length + ' file(s) selected';
  });
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bindUploadInput);
} else {
  bindUploadInput();
}

// ========== USER MANAGEMENT ==========
function addUser() {
  const name = document.getElementById('add-username').value;
  const role = document.getElementById('add-role').value;
  if (!name) return;
  setGradioVal('gv-uname', name);
  setGradioVal('gv-role', role);
  bridgeClick('gb-add-user');
  document.getElementById('add-username').value = '';
  setTimeout(refreshUsers, 800);
}

function removeUser() {
  const name = document.getElementById('remove-username').value;
  if (!name) return;
  setGradioVal('gv-rm-uname', name);
  bridgeClick('gb-remove-user');
  document.getElementById('remove-username').value = '';
  setTimeout(refreshUsers, 800);
}

function refreshUsers() { bridgeClick('gb-refresh-users'); }

// ========== TOAST NOTIFICATION SYSTEM ==========
function showToast(msg, type) {
  type = type || 'info';
  var icons = { success: '✅', error: '❌', info: 'ℹ️' };
  var toast = document.createElement('div');
  toast.className = 'toast ' + type;
  toast.innerHTML = '<span class="toast-icon">' + (icons[type]||'ℹ️') + '</span><span>' + msg + '</span>';
  document.getElementById('toast-container').appendChild(toast);
  requestAnimationFrame(function() { toast.classList.add('show'); });
  setTimeout(function() {
    toast.classList.add('hide');
    setTimeout(function() { toast.remove(); }, 400);
  }, 3500);
}

// ========== CONFIRMATION MODAL ==========
var _modalCallback = null;
function confirmModal(title, msg, btnLabel, callback) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-msg').textContent = msg;
  var btn = document.getElementById('modal-confirm');
  btn.textContent = btnLabel;
  btn.className = 'btn btn-stop btn-sm';
  _modalCallback = callback;
  document.getElementById('modal-overlay').classList.add('show');
}
function modalConfirm() {
  document.getElementById('modal-overlay').classList.remove('show');
  if (_modalCallback) { _modalCallback(); _modalCallback = null; }
}
function modalClose() {
  document.getElementById('modal-overlay').classList.remove('show');
  _modalCallback = null;
}

// ========== BUTTON LOADING STATE ==========
function setBtnLoading(btnId, loading) {
  var btn = document.getElementById(btnId);
  if (!btn) return;
  if (loading) {
    btn.classList.add('loading');
    btn.dataset.origText = btn.textContent;
    btn.textContent = '⏳ Working...';
  } else {
    btn.classList.remove('loading');
    if (btn.dataset.origText) btn.textContent = btn.dataset.origText;
  }
}

// ========== CONSOLE WORD WRAP TOGGLE ==========
function toggleWrap() {
  var cw = document.getElementById('console-wrap');
  if (cw) cw.classList.toggle('nowrap');
}

// ========== DRAG-AND-DROP UPLOAD ==========
function initDropZone() {
  var dz = document.getElementById('drop-zone');
  if (!dz) return;
  dz.addEventListener('dragover', function(e) { e.preventDefault(); dz.classList.add('dragover'); });
  dz.addEventListener('dragleave', function() { dz.classList.remove('dragover'); });
  dz.addEventListener('drop', function(e) {
    e.preventDefault();
    dz.classList.remove('dragover');
    var files = e.dataTransfer.files;
    if (!files.length) return;
    var dt = new DataTransfer();
    for (var i = 0; i < files.length; i++) dt.items.add(files[i]);
    var hidden = document.querySelector('#gv-upload input[type="file"]');
    if (hidden) {
      var proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'files').set;
      proto.call(hidden, dt.files);
      hidden.dispatchEvent(new Event('change', { bubbles: true }));
    }
    document.getElementById('upload-files-label').textContent = files.length + ' file(s) dropped';
    bridgeClick('gb-upload');
  });
}

// ========== KEYBOARD SHORTCUTS ==========
document.addEventListener('keydown', function(e) {
  // Ctrl+S: Save file
  if (e.ctrlKey && e.key === 's') {
    e.preventDefault();
    var editorTab = document.getElementById('tab-files');
    if (editorTab && editorTab.classList.contains('active')) saveFile();
  }
  // Ctrl+R or F5: Refresh current tab
  if ((e.ctrlKey && e.key === 'r') || e.key === 'F5') {
    e.preventDefault();
    var activeTab = document.querySelector('.sidebar-tab.active');
    if (activeTab) {
      var tab = activeTab.dataset.tab;
      if (tab === 'console') refreshConsole();
      else if (tab === 'files') refreshDir();
      else if (tab === 'users') refreshUsers();
      else if (tab === 'settings') loadSettings();
    }
  }
  // Esc: Close modal
  if (e.key === 'Escape') modalClose();
});

// ========== CLICKABLE BREADCRUMB ==========
function makeBreadcrumb(pathStr) {
  var el = document.getElementById('current-path');
  if (!el || !pathStr) return;
  el.innerHTML = '';
  var parts = pathStr.split('/').filter(Boolean);
  var cumulative = '';
  for (var i = 0; i < parts.length; i++) {
    cumulative += (i === 0 ? '' : '/') + parts[i];
    var seg = document.createElement('span');
    seg.className = 'path-segment';
    seg.textContent = parts[i];
    (function(relPath) {
      seg.onclick = function() {
        setGradioVal('gv-folder', '');
        // Navigate to this path segment
        _selectedFolder = '';
        _selectedFile = '';
        setGradioVal('gv-folder', relPath);
        bridgeClick('gb-enter-folder');
      };
    })(cumulative);
    el.appendChild(seg);
    if (i < parts.length - 1) {
      var sep = document.createElement('span');
      sep.textContent = ' / ';
      sep.style.color = 'var(--text-muted)';
      el.appendChild(sep);
    }
  }
  if (parts.length === 0) {
    el.textContent = '/root';
  }
}
var _cmdHistory = [];
var _cmdHistIdx = -1;

function sendCmd() {
  var inp = document.getElementById('console-cmd-input');
  var cmd = inp.value.trim();
  if (!cmd) return;
  _cmdHistory.push(cmd);
  _cmdHistIdx = _cmdHistory.length;
  setGradioVal('gv-cmd', cmd);
  bridgeClick('gb-send-cmd');
  inp.value = '';
  setTimeout(function() {
    var res = gradioVal('g-cmd-result');
    if (res) showToast(res, res.indexOf('✅') >= 0 ? 'success' : 'error');
  }, 800);
}

function handleCmdKey(e) {
  if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (_cmdHistIdx > 0) {
      _cmdHistIdx--;
      e.target.value = _cmdHistory[_cmdHistIdx] || '';
    }
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (_cmdHistIdx < _cmdHistory.length - 1) {
      _cmdHistIdx++;
      e.target.value = _cmdHistory[_cmdHistIdx] || '';
    } else {
      _cmdHistIdx = _cmdHistory.length;
      e.target.value = '';
    }
  }
}

// ========== FILE DOWNLOAD ==========
var _editorFilePath = '';
function downloadCurrentFile() {
  var fname = document.getElementById('editor-fname').textContent;
  if (!fname || fname === 'Select a file') return showToast('No file selected', 'error');
  setGradioVal('gv-download-path', fname);
  bridgeClick('gb-download-file');
  setTimeout(function() {
    var raw = gradioVal('g-download');
    if (!raw || raw.indexOf('|') < 0) return showToast('Download failed', 'error');
    var parts = raw.split('|');
    var name = parts[0], b64 = parts[1];
    var bin = atob(b64);
    var arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    var blob = new Blob([arr]);
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('Downloaded: ' + name, 'success');
  }, 1000);
}

// ========== SETTINGS ==========
function propToKey(k) {
  return k.replace(/-([a-z])/g, function(_, c) { return c.toUpperCase(); }).replace(/^-/, '');
}
function keyToProp(k) {
  return k.replace(/([A-Z])/g, '-$1').toLowerCase();
}

function loadSettings() {
  bridgeClick('gb-load-settings');
  setTimeout(function() {
    var raw = gradioVal('g-settings');
    if (!raw || raw === '{}') return showToast('No settings found', 'error');
    try {
      var props = JSON.parse(raw);
      var fields = {
        'difficulty': 's-difficulty', 'gamemode': 's-gamemode',
        'max-players': 's-max-players', 'view-distance': 's-view-distance',
        'simulation-distance': 's-sim-distance', 'spawn-protection': 's-spawn-protection',
        'level-name': 's-level-name', 'level-seed': 's-seed'
      };
      var bools = {
        'online-mode': 's-online-mode', 'pvp': 's-pvp',
        'allow-nether': 's-allow-nether', 'spawn-monsters': 's-spawn-monsters',
        'spawn-animals': 's-spawn-animals', 'force-gamemode': 's-force-gamemode',
        'white-list': 's-whitelist', 'enable-command-block': 's-cmd-block'
      };
      for (var prop in fields) {
        var el = document.getElementById(fields[prop]);
        if (el && props[prop] !== undefined) el.value = props[prop];
      }
      for (var prop in bools) {
        var el = document.getElementById(bools[prop]);
        if (el && props[prop] !== undefined) el.checked = props[prop] === 'true';
      }
      showToast('Settings loaded from disk', 'success');
    } catch(e) { showToast('Error parsing settings', 'error'); }
  }, 800);
}

function saveSettings() {
  var props = {};
  var fields = {
    'difficulty': 's-difficulty', 'gamemode': 's-gamemode',
    'max-players': 's-max-players', 'view-distance': 's-view-distance',
    'simulation-distance': 's-sim-distance', 'spawn-protection': 's-spawn-protection',
    'level-name': 's-level-name', 'level-seed': 's-seed'
  };
  var bools = {
    'online-mode': 's-online-mode', 'pvp': 's-pvp',
    'allow-nether': 's-allow-nether', 'spawn-monsters': 's-spawn-monsters',
    'spawn-animals': 's-spawn-animals', 'force-gamemode': 's-force-gamemode',
    'white-list': 's-whitelist', 'enable-command-block': 's-cmd-block'
  };
  for (var prop in fields) {
    var el = document.getElementById(fields[prop]);
    if (el) props[prop] = el.value;
  }
  for (var prop in bools) {
    var el = document.getElementById(bools[prop]);
    if (el) props[prop] = el.checked ? 'true' : 'false';
  }
  setGradioVal('gv-settings-data', JSON.stringify(props));
  bridgeClick('gb-save-settings');
  setTimeout(function() {
    var res = gradioVal('g-cmd-result');
    if (res) showToast(res, res.indexOf('✅') >= 0 ? 'success' : 'error');
  }, 800);
}

// Export functions to window so inline onclick="..." handlers in the HTML can reach them
Object.assign(window, {
  bridgeClick, refreshConsole, switchTab, refreshDir, clickFolder, clickFile, reloadFile, saveFile,
  loadMore, createItem, renameItem, deleteItem, uploadFiles, addUser, removeUser, refreshUsers,
  sendCmd, handleCmdKey, downloadCurrentFile, loadSettings, saveSettings, showToast,
  confirmModal, modalConfirm, modalClose, setBtnLoading, toggleWrap, initDropZone, makeBreadcrumb
});

// ========== POLLING LOOP ==========
function pollGradio() {
  // Status
  var st = gradioVal('g-status');
  var running = st.indexOf('Running') >= 0 || st.indexOf('🟢') >= 0;
  var badge = document.getElementById('status-badge');
  var dot = document.getElementById('status-dot');
  var txt = document.getElementById('status-text');
  badge.className = 'status-badge ' + (running ? 'running' : 'stopped');
  dot.className = 'status-dot ' + (running ? 'running' : 'stopped');
  txt.textContent = running ? 'Running' : 'Stopped';
  document.getElementById('stat-status').textContent = running ? '🟢 Running' : '🔴 Stopped';

  // Console (debounced: only update if changed)
  var con = gradioVal('g-console');
  var ct = document.getElementById('console-text');
  if (con !== undefined && con !== null && con !== _lastConVal) {
    _lastConVal = con;
    var atBottom = ct.scrollHeight - ct.scrollTop - ct.clientHeight < 40;
    ct.textContent = con || '[No logs yet — start the server from the Console tab]';
    if (atBottom) ct.scrollTop = ct.scrollHeight;
  }

  // Path (clickable breadcrumb)
  var p = gradioVal('g-path');
  if (p) {
    var pp = p.replace(/^.*\/root/, '/root').replace(/^📁 /, '');
    makeBreadcrumb(pp);
  }

  // Folders
  var fld = gradioVal('g-folders');
  if (fld) {
    try {
      var fl = JSON.parse(fld);
      renderFolderList(fl);
    } catch(e) {}
  }

  // Files
  var fil = gradioVal('g-files');
  if (fil) {
    try {
      var fl2 = JSON.parse(fil);
      renderFileList(fl2);
    } catch(e) {}
  }

  // Editor content
  var ec = gradioVal('g-editor');
  if (ec) {
    document.getElementById('editor-content').value = ec;
  }

  // Editor title
  var et = gradioVal('g-editor-title');
  if (et) {
    var match = et.match(/`([^`]+)`/);
    if (match) document.getElementById('editor-fname').textContent = match[1];
  }

  // Has more
  var hm = gradioVal('g-editor-has-more');
  document.getElementById('btn-load-more').style.display = (hm === 'True' || hm === 'true' || hm === '1') ? '' : 'none';

  // Users
  var us = gradioVal('g-users');
  if (us) document.getElementById('users-list').innerHTML = us.replace(/\n/g, '<br>');

  // Resources (CPU/RAM/Disk)
  var res = gradioVal('g-resources');
  if (res) {
    try {
      var r = JSON.parse(res);
      document.getElementById('stat-cpu').textContent = r.cpu + '%';
      document.getElementById('stat-cpu-sub').textContent = 'Usage';
      document.getElementById('stat-memory').textContent = r.ram_used + ' / ' + r.ram_total + ' GB';
      document.getElementById('stat-memory-pct').textContent = r.ram_pct + '%';
      document.getElementById('stat-memory-bar').style.width = r.ram_pct + '%';
      document.getElementById('stat-uptime').textContent = 'Uptime: ' + r.uptime;
    } catch(e) {}
  }

  // Players
  var pl = gradioVal('g-players');
  if (pl !== undefined && pl !== null) {
    var names = pl.trim();
    var count = names && names !== 'No players online' ? names.split(',').length : 0;
    document.getElementById('stat-players').textContent = count;
    document.getElementById('stat-players-list').textContent = names || 'No players online';
  }

  // Operation status (show toasts on change)
  var op = gradioVal('g-op');
  if (op && op !== _lastOpVal) {
    _lastOpVal = op;
    var targets = ['op-status-console', 'op-status-files', 'op-status-users', 'op-status-settings'];
    var color = op.indexOf('✅') >= 0 ? 'var(--mc-green)' : (op.indexOf('❌') >= 0 || op.indexOf('⛔') >= 0 ? 'var(--mc-red)' : 'var(--text-secondary)');
    for (var t of targets) {
      var el = document.getElementById(t);
      if (el) { el.textContent = op; el.style.color = color; }
    }
    // Toast for important messages
    if (op.indexOf('✅') >= 0) showToast(op.replace(/✅\s*/, ''), 'success');
    else if (op.indexOf('❌') >= 0 || op.indexOf('⛔') >= 0) showToast(op.replace(/[❌⛔]\s*/, ''), 'error');
  }

  // ─── Throttled backend refreshes (driven by this reliable poll loop) ───
  _pollCount++;
  try {
    bridgeClick('gb-refresh-con');                 // console: every poll (~1.5s)
    if (_pollCount % 2 === 0) bridgeClick('gb-periodic-status');   // status ~3s
    if (_pollCount % 3 === 0) bridgeClick('gb-refresh-dir');       // files ~4.5s
    if (_pollCount % 3 === 0) bridgeClick('gb-refresh-res');       // resources ~4.5s
    if (_pollCount % 4 === 0) bridgeClick('gb-refresh-players');   // players ~6s
    if (_pollCount % 6 === 0) bridgeClick('gb-refresh-users');     // users ~9s
  } catch (e) {}
}

function renderFolderList(folders) {
  var el = document.getElementById('folder-list');
  var html = '';
  if (folders.length === 0) {
    html = '<div class="empty-state"><div class="empty-icon">📂</div><div class="empty-text">No folders</div></div>';
  } else {
    for (var i = 0; i < folders.length; i++) {
      var f = folders[i];
      var active = f === _selectedFolder ? ' active' : '';
      html += '<div class="file-item folder' + active + '" tabindex="0" role="button" style="animation-delay:' + (i * 25) + 'ms" onclick="clickFolder(\'' + f.replace(/'/g, "\\'") + '\')" onkeydown="if(event.key===\'Enter\')clickFolder(\'' + f.replace(/'/g, "\\'") + '\')"><span class="icon" aria-hidden="true">📁</span> ' + f + '</div>';
    }
  }
  el.innerHTML = html;
}

function renderFileList(files) {
  var el = document.getElementById('file-list');
  var html = '';
  if (files.length === 0) {
    html = '<div class="empty-state"><div class="empty-icon">📄</div><div class="empty-text">No text files</div></div>';
  } else {
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      var active = f === _selectedFile ? ' active' : '';
      var ext = f.split('.').pop().toLowerCase();
      var icon = '📄';
      if (ext === 'yml' || ext === 'yaml') icon = '📋';
      else if (ext === 'json') icon = '{ }';
      else if (ext === 'properties') icon = '⚙️';
      else if (ext === 'txt' || ext === 'log') icon = '📝';
      else if (ext === 'xml') icon = '📑';
      html += '<div class="file-item' + active + '" tabindex="0" role="button" style="animation-delay:' + (i * 25) + 'ms" onclick="clickFile(\'' + f.replace(/'/g, "\\'") + '\')" onkeydown="if(event.key===\'Enter\')clickFile(\'' + f.replace(/'/g, "\\'") + '\')"><span class="icon" aria-hidden="true">' + icon + '</span> ' + f + '</div>';
    }
  }
  el.innerHTML = html;
}

// Counter for throttled backend refreshes (driven by the reliable poll loop)
var _pollCount = 0;
var _lastConVal = '';
var _lastOpVal = '';

// Start poll loop + init drag-drop
setTimeout(function() {
  // Force-hide bridge components (backup for Gradio CSS)
  var bw = document.getElementById('bridge-wrap');
  if (bw) {
    bw.style.cssText = 'display:none!important;height:0!important;overflow:hidden!important;padding:0!important;margin:0!important;border:none!important';
  }

  pollGradio();
  setInterval(pollGradio, 1500);
  initDropZone();
}, 100);
"""

with gr.Blocks(title="MC Server Panel", css="""
#bridge-wrap .gradio-group,
#bridge-wrap .gradio-textbox,
#bridge-wrap .gradio-button,
#bridge-wrap .gradio-checkbox,
#bridge-wrap .gradio-file,
#bridge-wrap [data-testid="textbox"],
#bridge-wrap [data-testid="button"],
#bridge-wrap [data-testid="checkbox"],
#bridge-wrap [data-testid="file"] {
  display:none!important;height:0!important;overflow:hidden!important;
  padding:0!important;margin:0!important;border:none!important;
  min-height:0!important;max-height:0!important;
}
""", head="<script>\n" + DASHBOARD_JS + "\n</script>") as demo:
    demo.load(fn=activate_gpu, inputs=None, outputs=gr.Textbox(visible=False))

    current_path_state = gr.State("")
    file_path_state = gr.State("")
    load_offset_state = gr.State(0)

    current_user = gr.State(None)

    # ─── Custom dashboard (renders FIRST so it's the visible UI) ───
    gr.HTML(value=DASHBOARD_HTML)

    # ─── ALL bridge components hidden in a single container ───
    with gr.Column(elem_id="bridge-wrap", visible=False):
        # Bridge outputs
        _console = gr.Textbox(elem_id="g-console")
        _status = gr.Textbox(elem_id="g-status")
        _path = gr.Textbox(elem_id="g-path")
        _folders = gr.Textbox(elem_id="g-folders")
        _files = gr.Textbox(elem_id="g-files")
        _op = gr.Textbox(elem_id="g-op")
        _editor = gr.Textbox(elem_id="g-editor")
        _editor_title = gr.Textbox(elem_id="g-editor-title")
        _editor_fpath = gr.Textbox(elem_id="g-editor-fpath")
        _editor_offset = gr.Textbox(elem_id="g-editor-offset")
        _editor_has_more = gr.Textbox(elem_id="g-editor-has-more")
        _users = gr.Textbox(elem_id="g-users")
        _resources = gr.Textbox(elem_id="g-resources")
        _players = gr.Textbox(elem_id="g-players")
        _cmd_result = gr.Textbox(elem_id="g-cmd-result")
        _download_data = gr.Textbox(elem_id="g-download")
        _settings = gr.Textbox(elem_id="g-settings")

        # Bridge buttons
        _b_start = gr.Button(elem_id="gb-start")
        _b_stop = gr.Button(elem_id="gb-stop")
        _b_restart = gr.Button(elem_id="gb-restart")
        _b_refresh_con = gr.Button(elem_id="gb-refresh-con")
        _b_refresh_dir = gr.Button(elem_id="gb-refresh-dir")
        _b_enter_folder = gr.Button(elem_id="gb-enter-folder")
        _b_select_file = gr.Button(elem_id="gb-select-file")
        _b_save_file = gr.Button(elem_id="gb-save-file")
        _b_load_more = gr.Button(elem_id="gb-load-more")
        _b_create = gr.Button(elem_id="gb-create")
        _b_rename = gr.Button(elem_id="gb-rename")
        _b_delete = gr.Button(elem_id="gb-delete")
        _b_upload = gr.Button(elem_id="gb-upload")
        _b_add_user = gr.Button(elem_id="gb-add-user")
        _b_remove_user = gr.Button(elem_id="gb-remove-user")
        _b_refresh_users = gr.Button(elem_id="gb-refresh-users")
        _b_periodic_con = gr.Button(elem_id="gb-periodic-con")
        _b_periodic_status = gr.Button(elem_id="gb-periodic-status")
        _b_periodic_dir = gr.Button(elem_id="gb-periodic-dir")
        _b_periodic_users = gr.Button(elem_id="gb-periodic-users")
        _b_send_cmd = gr.Button(elem_id="gb-send-cmd")
        _b_refresh_res = gr.Button(elem_id="gb-refresh-res")
        _b_refresh_players = gr.Button(elem_id="gb-refresh-players")
        _b_download_file = gr.Button(elem_id="gb-download-file")
        _b_load_settings = gr.Button(elem_id="gb-load-settings")
        _b_save_settings = gr.Button(elem_id="gb-save-settings")

        # Bridge variable inputs
        _v_folder = gr.Textbox(elem_id="gv-folder")
        _v_file = gr.Textbox(elem_id="gv-file")
        _v_content = gr.Textbox(elem_id="gv-content")
        _v_name = gr.Textbox(elem_id="gv-name")
        _v_type = gr.Textbox(elem_id="gv-type", value="File")
        _v_old = gr.Textbox(elem_id="gv-old")
        _v_del_folder = gr.Checkbox(elem_id="gv-del-folder", value=False)
        _v_uname = gr.Textbox(elem_id="gv-uname")
        _v_role = gr.Textbox(elem_id="gv-role", value="editor")
        _v_rm_uname = gr.Textbox(elem_id="gv-rm-uname")
        _v_upload = gr.File(elem_id="gv-upload", file_count="multiple")
        _v_cmd = gr.Textbox(elem_id="gv-cmd")
        _v_download_path = gr.Textbox(elem_id="gv-download-path")
        _v_settings_data = gr.Textbox(elem_id="gv-settings-data")

    # ─── Wrapper: scan directory returns JSON ───
    async def w_scan_directory(rel):
        target = get_safe_path(rel)
        folders = []
        files = []
        try:
            entries = await asyncio.wait_for(
                asyncio.to_thread(lambda: list(os.listdir(target))), timeout=5.0
            )
            for item in entries:
                fp = os.path.join(target, item)
                try:
                    if await asyncio.to_thread(os.path.isdir, fp):
                        folders.append(item)
                    else:
                        ext = os.path.splitext(item)[1].lower()
                        if ext not in BINARY_EXTENSIONS:
                            files.append(item)
                except:
                    files.append(item)
        except:
            pass
        folders.sort()
        files.sort()
        path_display = f"/root/{rel}" if rel else "/root"
        return path_display, json.dumps(folders), json.dumps(files)

    # ─── Wrapper: enter folder ───
    async def w_enter_folder(folder, rel):
        if rel is None:
            rel = ""
        if not folder:
            return rel, *await w_scan_directory(rel)
        if folder == ".. (المجلد الأعلى)":
            if not rel:
                return "", *await w_scan_directory("")
            parts = rel.strip("/").split("/")
            parent = "/".join(parts[:-1])
            return parent, *await w_scan_directory(parent)
        new_rel = os.path.join(rel, folder).strip("/")
        return new_rel, *await w_scan_directory(new_rel)

    # ─── Wrapper: load file content ───
    async def w_load_file(file, rel):
        r = await load_file_content(file, rel)
        content = r[0]
        if isinstance(content, dict):
            content = content.get("value", "")
        title = r[1]
        if isinstance(title, dict):
            title = title.get("value", "")
        has_more = False
        if isinstance(r[6], dict):
            has_more = r[6].get("visible", False)
        return content, title, str(r[4]), str(r[5]), str(has_more)

    # ─── Wrapper: load more ───
    async def w_load_more(path, offset_str):
        try:
            offset = int(offset_str)
        except:
            offset = 0
        r = await load_more_content(path, offset)
        content = r[0]
        if isinstance(content, dict):
            content = content.get("value", "")
        has_more = False
        if isinstance(r[2], dict):
            has_more = r[2].get("visible", False)
        return content, str(r[1]), str(has_more)

    # ─── Wrapper: create item ───
    async def w_create(name, typ, rel, user):
        r = await create_item(name, typ, rel, user)
        return r[0], *await w_scan_directory(rel)

    # ─── Wrapper: rename item ───
    async def w_rename(old, new, rel, user):
        r = await rename_item(old, new, rel, user)
        return r[0], *await w_scan_directory(rel)

    # ─── Wrapper: delete item ───
    async def w_delete(name, is_folder, rel, user):
        r = await delete_item(name, is_folder, rel, user)
        return r[0], *await w_scan_directory(rel)

    # ─── Wrapper: upload ───
    async def w_upload(files, rel, user):
        r = await upload_to_current_dir(files, rel, user)
        return r[0], *await w_scan_directory(rel)

    # ─── User management wrappers ───
    def w_list_users():
        users = load_users()
        if not users:
            return "_No users configured_"
        lines = []
        for u, r in sorted(users.items()):
            icon = {"admin": "🛡️", "editor": "✏️", "viewer": "👁️"}.get(r, "❓")
            lines.append(f"- {icon} **{u}** → `{r}`")
        return "\n".join(lines)

    def w_add_user(name, role, user):
        if not has_perm(user, "users_manage"):
            return "⛔ Only admins can manage users"
        if not name:
            return "⚠️ Enter a username"
        users = load_users()
        users[name.strip()] = role
        save_users(users)
        return f"✅ Added **{name.strip()}** as `{role}`"

    def w_remove_user(name, user):
        if not has_perm(user, "users_manage"):
            return "⛔ Only admins can manage users"
        if not name:
            return "⚠️ Enter a username"
        users = load_users()
        u = name.strip()
        if u in users:
            del users[u]
            save_users(users)
            return f"🗑️ Removed **{u}**"
        return f"⚠️ User **{u}** not found"

    # ─── Phase 2: New wrappers ───
    def w_send_cmd(cmd, user):
        return send_console_command(cmd, user)

    def w_get_resources():
        return json.dumps(get_system_resources())

    def w_get_players():
        return ", ".join(get_online_players()) or "No players online"

    def w_download_file(filepath, rel, user):
        if not has_perm(user, "files_read"):
            return "ERROR:Permission denied"
        if not filepath:
            return ""
        try:
            target = resolve_safe_child_path(rel, filepath)
        except ValueError:
            return "ERROR:Invalid path"
        if not os.path.isfile(target):
            return ""
        try:
            size = os.path.getsize(target)
            if size > 5 * 1024 * 1024:
                return "ERROR:File too large (>5MB)"
            with open(target, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            return f"{filepath}|{data}"
        except:
            return ""

    def w_load_settings():
        props_path = os.path.join(WORKDIR, "server.properties")
        if not os.path.exists(props_path):
            return "{}"
        try:
            props = {}
            with open(props_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        props[k.strip()] = v.strip()
            return json.dumps(props)
        except:
            return "{}"

    def w_save_settings(data_str, user):
        if not has_perm(user, "files_write"):
            return "⛔ Permission denied"
        props_path = os.path.join(WORKDIR, "server.properties")
        try:
            props = json.loads(data_str)
            with open(props_path, "w") as f:
                for k, v in sorted(props.items()):
                    f.write(f"{k}={v}\n")
            return "✅ Settings saved. Restart server to apply."
        except Exception as e:
            return f"❌ Error saving: {e}"

    # ─── Event handlers ───
    _b_start.click(fn=control_server, inputs=[gr.State("START"), current_user], outputs=_status)
    _b_stop.click(fn=control_server, inputs=[gr.State("STOP"), current_user], outputs=_status)
    _b_restart.click(fn=control_server, inputs=[gr.State("RESTART"), current_user], outputs=_status)
    _b_refresh_con.click(fn=get_logs, outputs=_console)
    _b_refresh_dir.click(fn=w_scan_directory, inputs=current_path_state, outputs=[_path, _folders, _files])
    _b_enter_folder.click(fn=w_enter_folder, inputs=[_v_folder, current_path_state], outputs=[current_path_state, _path, _folders, _files])
    _b_select_file.click(fn=w_load_file, inputs=[_v_file, current_path_state], outputs=[_editor, _editor_title, _editor_fpath, _editor_offset, _editor_has_more])
    _b_save_file.click(fn=save_file_content, inputs=[_v_file, _v_content, current_path_state, current_user], outputs=_op)
    _b_load_more.click(fn=w_load_more, inputs=[_editor_fpath, _editor_offset], outputs=[_editor, _editor_offset, _editor_has_more])
    _b_create.click(fn=w_create, inputs=[_v_name, _v_type, current_path_state, current_user], outputs=[_op, _path, _folders, _files])
    _b_rename.click(fn=w_rename, inputs=[_v_old, _v_name, current_path_state, current_user], outputs=[_op, _path, _folders, _files])
    _b_delete.click(fn=w_delete, inputs=[_v_old, _v_del_folder, current_path_state, current_user], outputs=[_op, _path, _folders, _files])
    _b_upload.click(fn=w_upload, inputs=[_v_upload, current_path_state, current_user], outputs=[_op, _path, _folders, _files])
    _b_add_user.click(fn=w_add_user, inputs=[_v_uname, _v_role, current_user], outputs=_op)
    _b_remove_user.click(fn=w_remove_user, inputs=[_v_rm_uname, current_user], outputs=_op)
    _b_refresh_users.click(fn=w_list_users, outputs=_users)

    _b_periodic_con.click(fn=get_logs, outputs=_console)
    _b_periodic_status.click(fn=get_server_status, outputs=_status)
    _b_periodic_dir.click(fn=w_scan_directory, inputs=current_path_state, outputs=[_path, _folders, _files])
    _b_periodic_users.click(fn=w_list_users, outputs=_users)

    # ─── Phase 2: New event handlers ───
    _b_send_cmd.click(fn=w_send_cmd, inputs=[_v_cmd, current_user], outputs=_cmd_result)
    _b_refresh_res.click(fn=w_get_resources, outputs=_resources)
    _b_refresh_players.click(fn=w_get_players, outputs=_players)
    _b_download_file.click(fn=w_download_file, inputs=[_v_download_path, current_path_state, current_user], outputs=_download_data)
    _b_load_settings.click(fn=w_load_settings, outputs=_settings)
    _b_save_settings.click(fn=w_save_settings, inputs=[_v_settings_data, current_user], outputs=_cmd_result)

    # ─── Auth-aware initialisation ───
    def w_init_user(request: gr.Request):
        user = resolve_current_user(request)
        _bootstrap_admin(user)
        return user

    # ─── Initial loads (one time, no `every`) ───
    demo.load(fn=w_init_user, inputs=None, outputs=current_user)
    demo.load(fn=get_logs, outputs=_console)
    demo.load(fn=get_server_status, outputs=_status)
    demo.load(fn=w_scan_directory, inputs=current_path_state, outputs=[_path, _folders, _files])
    demo.load(fn=w_list_users, outputs=_users)

demo.queue(default_concurrency_limit=3)
log("[SYSTEM] MC Server Panel initialized. Server directory: " + WORKDIR)
log("[SYSTEM] Use the Console tab → Start Server to launch Minecraft.")


def main():
    """Entry-point: optionally auto-start the Minecraft server, then launch Gradio."""
    log("[SYSTEM] Starting Gradio interface …")

    auto_start = os.environ.get("AUTO_START_SERVER", "").lower() in ("1", "true", "yes")
    if auto_start:
        log("[SYSTEM] AUTO_START_SERVER is enabled — launching Minecraft server …")
        threading.Thread(target=start_server_backend, daemon=True).start()

    demo.launch()


if __name__ == "__main__":
    main()