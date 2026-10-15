import os
import sys

os.environ["APP_ENV"] = "development"
os.environ["DATABASE_URL"] = "postgresql+psycopg://postgres@localhost/signin_auth"
sys.path.insert(0, ".")

import database
from sqlalchemy import inspect

with database.engine.connect() as conn:
    insp = inspect(conn)
    cols = {c["name"]: c for c in insp.get_columns("users")}

role = cols.get("role")
print("role column present:", role is not None)
if role is not None:
    print("nullable:", role.get("nullable"))
    print("default:", role.get("default"))
    print("type:", role.get("type"))

    count = conn.exec_driver_sql(
        "SELECT COUNT(*) AS c FROM users WHERE role IS NULL"
    ).scalar()
    print("users with null role:", count)
