import sqlite3

class ContentModel:
    @staticmethod
    def get_content():
        conn = sqlite3.connect('church_database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT section_name, content FROM content")
        content = {row["section_name"]: row["content"] for row in cursor.fetchall()}
        conn.close()
        return content

    @staticmethod
    def update_content(section_name, new_content):
        conn = sqlite3.connect('church_database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE content SET content = ? WHERE section_name = ?", (new_content, section_name))
        conn.commit()
        conn.close()
        return True
