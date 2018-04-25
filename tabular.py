#!/usr/bin/python
from query import *

#File per la stesura di indirizzi ip
ip_addresses = open('indirizzi_ip.log','w')

def hline():
	print "-" * 30

hline()
d = Honeyanalysis()
conns = d.trackConnections()
hline()
#Statistiche sulle porte
portstats = d.protoStats()
print "Attacchi|", "Protocollo"
hline()
for item in portstats:
	print item[0], "\t|", item[1]
hline()

#numero di credenziali per Protocollo
numLoginsPerPort = d.CredenzialiPerProtocollo()
print "#Logins |", "Protocollo"
passwordstats= d.defaultPasswords()
hline()
for item in numLoginsPerPort:
	print item[0], "\t|", item[1]

hline()
print "Password |", "Numero"
for item in passwordstats:
	print item[1], "\t|", item[0]
hline()


#routine per listare gli indirizzi ip. Generare script che da indirizzi ip si ottiene il nome del server e lo si scrive su file.
ipstats=d.uniqueIPS()
hline()
for item in ipstats:
	ip_addresses.write("%s\n" % item)

hline()

"""
downloadstats=d.downloadsToHash()
for item in downloadstats:
	print item[1], "\t|", item[0]
"""
