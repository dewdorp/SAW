"""Alembic environment: uses the engine passed by saw.storage.migrate (no URL in config files)."""
from alembic import context

from saw.storage.db import Base, load_models

load_models()
target_metadata = Base.metadata
engine = context.config.attributes["engine"]

with engine.connect() as connection:
    sqlite = connection.dialect.name == "sqlite"
    if sqlite:
        # batch mode rebuilds tables (copy → drop → rename); with foreign keys enforced the DROP of a parent table
        # that has rows fails. PRAGMA foreign_keys only takes effect outside a transaction.
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.commit()
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=sqlite,
                      compare_type=True)
    with context.begin_transaction():
        context.run_migrations()
    connection.commit()
    if sqlite:  # the connection returns to the application's pool: enforce foreign keys again
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.commit()
