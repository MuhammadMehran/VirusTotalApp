
from db import get_db

class FileModel():
    def __init__(self, id_, name, resource):
        self.id = id_
        self.name = name
        self.resource = resource

    @staticmethod
    def get(resource):
        db = get_db()
        file_ = db.execute(
            "SELECT * FROM file WHERE resource = ?", (resource,)
        ).fetchone()
        if not file_:
            return None

        file_ = FileModel(
            id_=file_[0], name=file_[1], resource=file_[2]
        )
        return file_

    @staticmethod
    def create(id_, name, resource):
        db = get_db()
        db.execute(
            "INSERT INTO file (id, name, resource) "
            "VALUES (?, ?, ?)",
            (id_, name, resource),
        )
        db.commit()
    @staticmethod
    def get_all():
        db = get_db()
        files = db.execute(
            "SELECT * FROM file").fetchall()
        return files
