from sqlalchemy.ext.declarative import declarative_base
import ckan.model as model
Base = declarative_base()
metadata = Base.metadata


def drop_tables():
  """Drop tables defined in model."""
  metadata.drop_all(model.meta.engine)


def create_tables():
  """Create tables defined in model."""
  metadata.create_all(model.meta.engine)
