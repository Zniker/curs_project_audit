from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.models import Base, AuditEvent
from app.parser import parse_log_file
from app.classifier import classify_event


def import_events(log_path="/var/log/audit/audit.log"):
    engine = create_engine("sqlite:///audit.db")
    Base.metadata.bind = engine
    session = Session(engine)

    events = parse_log_file(log_path)
    count_new = 0

    for ev in events:
        cls = classify_event(ev)

        # если нет файла (например, событие не PATH по нашим файлам) — пропускаем
        if not cls["file_path"]:
            continue

        # чтобы не создавать дубликаты — проверяем по audit_id + file_path
        stmt = select(AuditEvent).where(
            AuditEvent.audit_id == cls["audit_id"],
            AuditEvent.file_path == cls["file_path"],
        )
        existing = session.scalars(stmt).first()
        if existing:
            continue

        ae = AuditEvent(
            audit_id=cls["audit_id"],
            timestamp=cls["timestamp"],
            uid=cls["uid"],
            auid=cls["auid"],
            exe=cls["exe"],
            comm=cls["comm"],
            syscall=cls["syscall"],
            file_path=cls["file_path"],
            perm=cls["perm"],
            key=cls["key"],
            event_type=cls["event_type"],   # записываем тип события
            success=cls["success"],
            classification=cls["classification"],
            reason=cls["reason"],
        )

        session.add(ae)
        count_new += 1

    session.commit()
    session.close()
    print(f"Импорт завершён, добавлено {count_new} новых событий.")


if __name__ == "__main__":
    import_events()
