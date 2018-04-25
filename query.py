#!/usr/bin/python
#
#

import sqlite3 as lite

PATH_SQLITE = "/home/emanuele/Documenti/Dionaea/DionaeaDir/var/dionaea/logsql.sqlite"

class Honeyanalysis(object):

    def __init__(self):
        self.con = lite.connect(PATH_SQLITE)
        self.cur = self.con.cursor()

    def trackConnections(self):
        """ Traccia delle connessioni"""

        total = 0
        ttype = 0
        utype = 0
        otype = 0
        self.cur.execute("SELECT * from connections")
        conns = self.cur.fetchall()
        for num in conns:
            #Contatore delle connessioni
            if num[2] == "tcp":
                ttype += 1
            elif num[2] == "udp":
                utype += 1
            else:
                otype += 1
            total += + 1

        print "Numero # delle connessioni: %d" %total
        print "Totale # delle connessioni tcp %d" %ttype
        print "Totale # delle connessioni udp %d" %utype	
        print "Totale delle altre connessioni %d" %otype

    def protoStats(self):
        """ Routine per restituire il protocollo di connessione"""
        self.cur.execute("select count(connection_protocol) as count, connection_protocol from connections group by connection_protocol order by count desc")
        conns = self.cur.fetchall()
        data = self.parseData(conns)
        return data
    def defaultPasswords(self):
        """ Routine per restituire le password di default"""

        self.cur.execute("select count(logins.login_username||logins.login_password) as count, logins.login_username, logins.login_password, connections.connection_protocol, connections.local_port from logins, connections where connections.connection = logins.connection group by (logins.login_username||logins.login_password) order by count desc")
        conns = self.cur.fetchall()
        data = self.parseData(conns)
        return data

    def CredenzialiPerProtocollo(self):
        """ Routine per restituire il numero di logins sulla base del suo protocollo"""

        self.cur.execute("select count(logins.login_username) as count, connections.connection_protocol, connections.local_port from logins, connections where connections.connection = logins.connection group by (connections.local_port) order by count desc")
        conns = self.cur.fetchall()
        data = self.parseData(conns)
        return data



    def uniqueIPS(self):
        """Visualizzazione degli indirizzi IP """
        self.cur.execute("SELECT connections.remote_host FROM connections GROUP BY connections.remote_host")
        conns = self.cur.fetchall()
        data = self.parseData(conns)
        return data

    def downloadsToHash(self):
        """Mostra gli url e l'hash md5"""
        self.cur.execute("select download_url, download_md5_hash from downloads")
        conns = self.cur.fetchall()
        data = self.parseData(conns)
        return data

    def offers(self):
        """ Offers that correlate to downloadstohash """
        self.cur.execute("select * from offers")
        conns = self.cur.fetchall()
        data = self.parseData(conns)
        return data

    def sipVIA(self):
        """ IP sorgenti delle connessioni SIP"""
        total = 0
        self.cur.execute("select * from sip_vias")
        conns = self.cur.fetchall()
        data = self.parseData(conns)
        return data

    def parseData(self, data):
        buf = []
        for info in data:
            buf.append(info)
        return buf
