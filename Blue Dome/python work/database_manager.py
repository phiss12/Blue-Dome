import sqlite3

class DatabaseManager:
    def __init__(self, db_name):
        self.db_name = db_name
        self.conn = None
        self.cursor = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
    
    def execute_query(self, query, params=None):
        if self.conn is None or self.cursor is None:
            raise Exception("Database not connected. Call connect() first.")
        
        if params:
            self.cursor.execute(query, params)
        else:
            self.cursor.execute(query)
        
        self.conn.commit()
    
    def fetch_all(self, query, params=None):
        if self.conn is None or self.cursor is None:
            raise Exception("Database not connected. Call connect() first.")
        
        if params:
            self.cursor.execute(query, params)
        else:
            self.cursor.execute(query)
        
        return self.cursor.fetchall()

    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
       
        self.conn = None
        self.cursor = None