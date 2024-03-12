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
                    validFrom DATETIME,
                    validTo DATETIME
                    )
                    ''')

        commitAndClose(connection)

def insertCertficate(dbFile, commonName, validFrom, validTo):
    initializeDatabase(dbFile)
    connection = connectToDatabase(dbFile)
    if connection != None:
        cursor = connection.cursor()

        cursor.execute('''SELECT certificateId FROM certificates WHERE commonName = ?''', (commonName,))

        id = cursor.fetchone()

        if id:
            cursor.execute('''
                        UPDATE certificates SET commonName = ?, validFrom = ?, validTo = ? WHERE certificateId = ?
                        ''', (commonName, validFrom, validTo , id[0])
                        )
        else:
            cursor.execute('''
                        INSERT INTO certificates(commonName,validFrom,validTo)
                        VALUES (?, ?, ?)''', (commonName, validFrom, validTo)
                        )
        commitAndClose(connection)


def commitAndClose(connection):
    connection.commit()
    connection.close()
