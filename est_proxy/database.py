#!/usr/bin/python

import sqlite3

def connectToDatabase(dbFile):
    connection = None

    try:
        connection = sqlite3.connect(dbFile)
    except:
        print("Could not connect to database...")

    return connection

def initializeDatabase(dbFile):
    connection = connectToDatabase(dbFile)
    if connection != None:
        cursor = connection.cursor()
        cursor.execute('''
                    CREATE TABLE IF NOT EXISTS certificates
                    (
                    certificateId INTEGER PRIMARY KEY,
                    commonName TEXT,
                    issueDate DATETIME,
                    expireDate DATETIME
                    )
                    ''')

        commitAndClose(connection)

def insertCertficate(dbFile, commonName, issueDate, expireDate):
    initializeDatabase(dbFile)
    connection = connectToDatabase(dbFile)
    if connection != None:
        cursor = connection.cursor()

        cursor.execute('''SELECT certificateId FROM certificates WHERE commonName = ?''', (commonName,))

        id = cursor.fetchone()

        if id:
            cursor.execute('''
                        UPDATE certificates SET commonName = ?, issueDate = ?, expireDate = ? WHERE certificateId = ?
                        ''', (commonName, issueDate, expireDate, id[0])
                        )
        else:
            cursor.execute('''
                        INSERT INTO certificates(commonName,issueDate,expireDate)
                        VALUES (?, ?, ?)''', (commonName, issueDate, expireDate)
                        )
        commitAndClose(connection)


def commitAndClose(connection):
    connection.commit()
    connection.close()
