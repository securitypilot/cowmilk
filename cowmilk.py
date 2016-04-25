#!/usr/bin/env python

__author__ = "bdwit"
__description__ = "A simple web app to fetch and visualize your cowrie ssh honeypot data"

"""
Requirements (pip install <package>):
    * bottle
    * mysql-python
    * tabulate 
    * requests

Todo:
    * More/better sql queries
    * IP (geo)lookups
    * Hash lookups
    * Fancy template
"""

from bottle import get, post, run, template, request
from tabulate import tabulate
import requests
import MySQLdb as db
import re
import sys  

# Database settings, edit to your needs
DB_HOST = ""
DB_USER = ""
DB_PASS = ""
DB_NAME = ""

# Connect to database
connection = db.connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

@get("/attacks")
def attack_stats():
    # Attack statistics pivot page
    attacks = "<pre>"
    attacks += "<h2>Attacker Statistics</h2>"

    sql = []
    sql.append({"title":"Login attempts last 28 days",
                "sql":" SELECT date(timestamp) AS dateins,COUNT(session) AS occ\
                        FROM auth GROUP BY DATE(timestamp)\
                        ORDER BY timestamp DESC LIMIT 28",
               "columns":"Date,Amount"
    })
    sql.append({"title":"Top 25 SSH clients",
                "sql":" SELECT clients.version, COUNT(client)\
                        FROM sessions INNER JOIN clients ON sessions.client = clients.id\
                        GROUP BY sessions.client\
                        ORDER BY COUNT(client) DESC\
                        LIMIT 25",
                "columns":"Client,Amount"
    })
    sql.append({"title":"Usernames used yesterday",
                "sql":" SELECT username,COUNT(username) AS occ\
                        FROM auth\
                        WHERE username <> '' AND DATE(timestamp) = SUBDATE(CURDATE(),1)\
                        GROUP BY username ORDER BY COUNT(username) DESC",
                "columns":"Username,Amount"
    })
    sql.append({"title":"Passwords used yesterday",
                "sql":" SELECT password,COUNT(password) AS occ\
                        FROM auth\
                        WHERE password <> '' AND DATE(timestamp) = SUBDATE(CURDATE(),1)\
                        GROUP BY password ORDER BY COUNT(password) DESC",
                "columns":"Password,Amount"
    })
    sql.append({"title":"User/pass combinations yesterday",
                "sql":" SELECT username, password, COUNT(username) AS occ\
                        FROM auth\
                        WHERE username <> '' AND password <> '' AND DATE(timestamp) = SUBDATE(CURDATE(),1)\
                        GROUP BY username, password ORDER BY COUNT(username) DESC",
                "columns":"Username,Password,Amount"
    })

    # Get and present data
    with connection:
        for key in sql:
            cursor = connection.cursor()
            cursor.execute(key["sql"])
            rows = cursor.fetchall()
            columns = key["columns"].split(",")
            data = tabulate(rows, columns, tablefmt="rst")
            attacks += "<h3>{0}</h3>".format(key["title"])
            attacks += data + "<br>"

    attacks += "</pre>"
    return attacks

@get("/tty")
def tty_input():
    # Behaviour analysis pivot page
    cmd = "<pre>"
    cmd += "<h2>Behaviour Statistics</h2>"
   
    sql = []
    sql.append({"title":"CLI input today",
                "sql":" SELECT timestamp,input,success\
                        FROM input\
                        WHERE DATE(timestamp) = CURDATE()\
                        ORDER BY timestamp DESC",
                "columns":"Timestamp,Command,Successful"
    })
    sql.append({"title":"CLI input yesterday",
                "sql":" SELECT timestamp,input,success\
                        FROM input\
                        WHERE DATE(timestamp) = SUBDATE(CURDATE(),1)\
                        ORDER BY timestamp DESC",
                "columns":"Timestamp,Command,Successful"
    })
    sql.append({"title":"Interesting commands",
                "sql":" SELECT timestamp, input, success\
                        FROM input\
                        WHERE (input like '%cat%' OR input like '%dev%' OR input like '%man%' OR input like '%gpg%'\
                        OR input like '%ping%' OR input like '%ssh%' OR input like '%scp%' OR input like '%whois%'\
                        OR input like '%unset%' OR input like '%kill%' OR input like '%ifconfig%' OR input like '%iwconfig%' OR input like '%iptables%'\
                        OR input like '%traceroute%' OR input like '%screen%' OR input like '%user%')\
                        AND input NOT like '%wget%' AND input NOT like '%apt-get%'\
                        GROUP BY input\
                        ORDER BY timestamp DESC",
                "columns":"Timestamp,Command,Successful"
    })

    # Get and present data
    with connection:
        for key in sql:
            cursor = connection.cursor()
            cursor.execute(key["sql"])
            rows = cursor.fetchall()
            columns = key["columns"].split(",")
            data = tabulate(rows, columns, tablefmt="rst")
            cmd += "<h3>{0}</h3>".format(key["title"])
            cmd += data + "<br>"

    cmd += "</pre>"
    return cmd

@get("/intel")
def ip_intelligence():
    # IP intelligence pivot page
    intel = "<pre>"
    intel += "<h2>IP Intelligence</h2>"

    sql = []
    sql.append({"title":"Number of connections per IP today",
                "sql":" SELECT ip,COUNT(ip) AS occ\
                        FROM sessions\
                        WHERE DATE(starttime) = CURDATE()\
                        GROUP BY ip ORDER BY COUNT(ip) DESC",
                "columns":"IP address,Amount"
    })
    sql.append({"title":"Number of connections per IP yesterday",
                "sql":" SELECT ip,COUNT(ip) AS occ\
                        FROM sessions\
                        WHERE DATE(starttime) = SUBDATE(CURDATE(),1)\
                        GROUP BY ip ORDER BY COUNT(ip) DESC",
                "columns":"IP address,Amount"
    })
    sql.append({"title":"Overall IP activity",
                "sql":" SELECT A.*, B.success\
                        FROM (SELECT ip, MAX(starttime) as starttime, COUNT(DISTINCT sessions.id) as sessions FROM sessions GROUP BY ip) A LEFT JOIN (SELECT sessions.ip, MAX(success) as success FROM sessions, auth\
                        WHERE sessions.id = auth.session\
                        GROUP BY ip) B on A.ip = B.ip ORDER BY starttime DESC",
                 "columns":"IP Address,Last Seen,Sessions,Successful"
    })

    # Get and present data
    with connection:
        for key in sql:
            cursor = connection.cursor()
            cursor.execute(key["sql"])
            rows = cursor.fetchall()  
            columns = key["columns"].split(",")
            data = tabulate(rows, columns, tablefmt="rst")
            intel += "<h3>{0}</h3>".format(key["title"])
            intel += data + "<br>"
    
    intel += "</pre>"
    return intel

@get("/malwr")
def malware_analysis():
    # Malware analysis pivot page
    malwr = "<pre>"
    malwr += "<p><h2>Malware Analysis</h2></p><p></p>"

    sql = []
    sql.append({"title":"Succesful downloads today",
                "sql":" SELECT timestamp, input, TRIM(LEADING 'wget' FROM input) as file\
                        FROM input\
                        WHERE input LIKE '%wget%' AND input NOT LIKE 'wget' AND DATE(timestamp) = CURDATE()\
                        ORDER BY timestamp DESC",
                "columns":"Timestamp,Input,Location"
    })
    sql.append({"title":"Executed scripts today",
                "sql":" SELECT timestamp, input\
                        FROM input\
                        WHERE input LIKE '%./%' AND DATE(timestamp) = CURDATE()\
                        ORDER BY timestamp DESC",
                "columns":"Timestamp,Input"
    })
    sql.append({"title":"Succesful downloads yesterday",
                "sql":" SELECT timestamp, input, TRIM(LEADING 'wget' FROM input) as file\
                        FROM input\
                        WHERE input LIKE '%wget%' AND input NOT LIKE 'wget' AND DATE(timestamp) = SUBDATE(CURDATE(),1)\
                        ORDER BY timestamp DESC",
                "columns":"Timestamp,Input,Location"
    })
    sql.append({"title":"Executed scripts yesterday",
                "sql":" SELECT timestamp, input\
                        FROM input\
                        WHERE input LIKE '%./%' AND DATE(timestamp) = SUBDATE(CURDATE(),1)\
                        ORDER BY timestamp DESC",
                "columns":"Timestamp,Input"
    })

    # Get and present data
    with connection:
        for key in sql:
            cursor = connection.cursor()
            cursor.execute(key["sql"])
            rows = cursor.fetchall()
            columns = key["columns"].split(",")
            data = tabulate(rows, columns, tablefmt="rst")
            malwr += "<h3>{0}</h3>".format(key["title"])
            malwr += data + "<br>"
    
    malwr += "</pre>" 
    return malwr

# @get("/proxy")
# def proxy_abuse():
#     # Proxy abuse pivot page
#     proxy = "<pre>"
#     proxy += "<p><h2>SSH Proxy Abuse</h2></p><p></p>"
#     proxy += "</pre>"
#     return proxy

# Main page
@get("/")
def main():
    main = "<pre><center>"
    main += "<h1>Cowrie SSH Honeypot Analytics</h1>"
    main += "<h3><a href="+"/attacks"+">Attack Statistics</a><h3>"
    main += "<h3><a href="+"/tty"+">Behaviour Statistics</a><h3>"
    #main += "<h3><a href="+"/proxy"+">Proxy Abuse</a><h3>"
    main += "<h3><a href="+"/intel"+">IP Intelligence</a><h3>"
    main += "<h3><a href="+"/malwr"+">Malware Analysis</a><h3>"
    main += "</center></pre>"
    return main


# Run the webpage on port 8080
run(host='localhost', port=8080)