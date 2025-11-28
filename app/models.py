from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)

    audit_id = Column(String, index=True)   # ID из audit(...) в логе
    timestamp = Column(DateTime, default=datetime.utcnow)

    uid = Column(String)       # действующий UID
    auid = Column(String)      # аутентификационный UID
    exe = Column(String)       # путь к исполняемому файлу
    comm = Column(String)      # имя команды
    syscall = Column(String)   # номер системного вызова
    file_path = Column(String)
    perm = Column(String)
    key = Column(String)

    event_type = Column(String)       # тип события (accounts / privilege / ...)

    success = Column(Boolean)

    classification = Column(String)   # "normal" / "suspicious"
    reason = Column(String)           # текстовое объяснение
