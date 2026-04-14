"""
CYBERDUDEBIVASH AI — Database Migration Init
Run: alembic init alembic
     alembic revision --autogenerate -m "initial"
     alembic upgrade head
"""
# alembic/env.py template — run alembic init to generate the folder

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.database.models import Base
from core.settings import settings

target_metadata = Base.metadata
