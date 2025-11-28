# app/classifier.py

from pathlib import Path
import yaml

# --- доверенные пользователи/процессы ---

TRUSTED_ADMIN_UIDS = {"0"}  # root
TRUSTED_PROCESSES = {
    "/usr/bin/sudo",
    "/usr/bin/apt",
    "/usr/sbin/sshd",
    "/usr/sbin/useradd",
    "/usr/bin/passwd",
    "/usr/sbin/visudo",
    # системные службы, которые могут легитимно читать /etc/shadow
    "/usr/libexec/gdm-session-worker",
    "/usr/lib/systemd/systemd-executor",
}

# --- загрузка критических файлов из YAML ---

def _load_critical_files():
    """
    Читает critical_files.yaml из корня проекта.
    Возвращает dict: { path: {category, base_weight, description, ...}, ... }.
    """
    # app/classifier.py -> app/ -> .. -> корень проекта
    project_root = Path(__file__).resolve().parent.parent
    cfg_path = project_root / "critical_files.yaml"

    if not cfg_path.exists():
        # Фолбэк: пустой конфиг (ничего не считаем критичным)
        return {}

    with cfg_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    result = {}
    for entry in data.get("files", []):
        path = entry.get("path")
        if not path:
            continue
        result[path] = {
            "category": entry.get("category"),
            "base_weight": entry.get("base_weight", 0),
            "description": entry.get("description", ""),
        }
    return result


FILE_CONFIG = _load_critical_files()
CRITICAL_FILES = set(FILE_CONFIG.keys())


def classify_event(event_dict):
    """
    На вход:
      {
        'audit_id': str,
        'timestamp': datetime,
        'records': { 'SYSCALL': {...}, 'PATH': {...}, ... }
      }

    На выход: словарь полей для записи в БД (включая event_type).
    """
    records = event_dict.get("records", {})
    syscall = records.get("SYSCALL", {})
    path = records.get("PATH", {})

    uid = syscall.get("uid")
    auid = syscall.get("auid")
    exe = syscall.get("exe")
    comm = syscall.get("comm")
    syscall_nr = syscall.get("syscall")
    success = syscall.get("success") == "yes"

    file_path = path.get("name")
    perm = path.get("perm")
    key = path.get("key")

    # инфо о файле из YAML
    file_info = FILE_CONFIG.get(file_path)
    event_type = file_info["category"] if file_info else None
    base_weight = file_info["base_weight"] if file_info else 0

    classification = "normal"
    reason = "normal admin/system access"

    # --- базовая логика ---
    if file_path in CRITICAL_FILES:
        suspicious = False
        reason = "normal access"

        # auid >= 1000 — интерактивный пользователь (user1, kirill и т.д.)
        is_user = False
        try:
            if auid is not None and auid.isdigit() and int(auid) >= 1000:
                is_user = True
        except ValueError:
            pass

        is_admin = uid in TRUSTED_ADMIN_UIDS
        is_trusted_proc = exe in TRUSTED_PROCESSES

        # 1) интерактивный пользователь, не root и процесс не из списка доверенных
        if is_user and (not is_admin) and (not is_trusted_proc):
            suspicious = True
            reason = (
                f"user auid={auid}, uid={uid}, exe={exe} accessed {file_path} "
                f"(type={event_type}, base_weight={base_weight})"
            )

        # 2) Любая запись в критический файл — всегда подозрительно
        if perm and "w" in (perm or "") and success:
            suspicious = True
            reason = (
                f"write access to {file_path} (perm={perm}) by uid={uid}, exe={exe} "
                f"(type={event_type}, base_weight={base_weight})"
            )

        classification = "suspicious" if suspicious else "normal"

    return {
        "audit_id": event_dict.get("audit_id"),
        "timestamp": event_dict.get("timestamp"),
        "uid": uid,
        "auid": auid,
        "exe": exe,
        "comm": comm,
        "syscall": syscall_nr,
        "file_path": file_path,
        "perm": perm,
        "key": key,
        "success": success,
        "classification": classification,
        "reason": reason,
        "event_type": event_type,  # category из YAML
        # base_weight можно позже начать сохранять в БД, если захочешь
    }
