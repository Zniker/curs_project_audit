import re
from datetime import datetime

# пример: msg=audit(1716996845.123:456):
AUDIT_ID_RE = re.compile(r"audit\((\d+)\.\d+:(\d+)\)")


def parse_line(line: str):
    """
    Разбор одной строки из /var/log/audit/audit.log.
    Возвращает:
      {
        'type': 'SYSCALL' | 'PATH' | ...,
        'audit_id': 'sec:id',
        'fields': {...}
      }
    или None, если строка не подходит.
    """
    line = line.strip()
    if not line.startswith("type="):
        return None

    parts = line.split()
    record_type = parts[0].split("=", 1)[1]

    # ищем msg=...
    msg_part = next((p for p in parts if p.startswith("msg=")), None)
    if not msg_part:
        return None

    msg_value = msg_part.split("=", 1)[1]
    match = AUDIT_ID_RE.search(msg_value)
    if not match:
        return None

    sec, rec_id = match.groups()
    audit_id = f"{sec}:{rec_id}"
    timestamp = datetime.fromtimestamp(int(sec))

    fields = {"timestamp": timestamp}

    # остальные поля вида key=value
    for item in parts[1:]:
        if item.startswith("msg="):
            continue
        if "=" in item:
            key, value = item.split("=", 1)
            value = value.strip('"')
            fields[key] = value

    return {
        "type": record_type,
        "audit_id": audit_id,
        "fields": fields,
    }


def parse_log_file(path="/var/log/audit/audit.log"):
    """
    Читает лог auditd и собирает события по audit_id.
    Возвращает список словарей:
      {
        'audit_id': str,
        'timestamp': datetime,
        'records': {
            'SYSCALL': {...},
            'PATH': {...},
            ...
        }
      }
    """
    raw_events = {}

    with open(path, "r", errors="ignore") as f:
        for line in f:
            rec = parse_line(line)
            if not rec:
                continue

            aid = rec["audit_id"]
            rtype = rec["type"]
            fields = rec["fields"]

            ev = raw_events.get(aid)
            if ev is None:
                ev = {
                    "audit_id": aid,
                    "timestamp": fields.get("timestamp"),
                    "records": {}
                }
                raw_events[aid] = ev
            else:
                if not ev.get("timestamp") and fields.get("timestamp"):
                    ev["timestamp"] = fields["timestamp"]

            ev["records"][rtype] = fields

    return list(raw_events.values())
