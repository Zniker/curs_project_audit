from sqlalchemy import create_engine
from app.models import Base

engine = create_engine("sqlite:///audit.db")
Base.metadata.create_all(engine)
