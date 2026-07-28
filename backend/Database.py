"""
database.py
===========
Connexion SQLite + SQLAlchemy (Tâches B1.1 à B1.3 du Guide).

SQLite est utilisé tel que justifié dans la fiche (Section 6.3) :
aucune installation de serveur nécessaire, fichier unique portable,
largement suffisant pour le volume de données de ce projet. Le choix
de passer par SQLAlchemy (plutôt que du SQL brut) permet une migration
future vers PostgreSQL sans réécrire toute la logique métier, si le
projet grossit.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from Models import Base

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vulnwatch.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Crée les tables si elles n'existent pas encore (Tâche B1.3)."""
    Base.metadata.create_all(bind=engine)


def get_session():
    """À utiliser avec un `with` ou en dépendance FastAPI."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()