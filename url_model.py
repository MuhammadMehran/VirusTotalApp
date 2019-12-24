
from db import get_db

class UrlModel():
    def __init__(self, id_, name, resource):
        self.id = id_
        self.name = name
        self.resource = resource

    @staticmethod
    def get(resource):
        db = get_db()
        url = db.execute(
            "SELECT * FROM url WHERE resource = ?", (resource,)
        ).fetchone()
        if not url:
            return None

        url = UrlModel(
            id_=url[0], name=url[1], resource=url[2]
        )
        return url

    @staticmethod
    def create(id_, name, resource):
        db = get_db()
        db.execute(
            "INSERT INTO url (id, name, resource) "
            "VALUES (?, ?, ?)",
            (id_, name, resource),
        )
        db.commit()
    
    @staticmethod
    def get_all():
        db = get_db()
        files = db.execute(
            "SELECT * FROM url").fetchall()
        return files

