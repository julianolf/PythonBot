#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import socket
import sys
import urllib2
import os
import time
from pysqlite2 import dbapi2 as sqlite

channel = '#masmorra'
nick = 'carcereiro'
server = 'irc.oftc.net' 

def sendmsg(msg): 
    sock.send('PRIVMSG '+ channel + ' :' + str(msg) + '\r\n')

class db():
	def __init__(self, dbfile):
		if not os.path.exists(dbfile):
			self.conn = sqlite.connect(dbfile)
			self.cursor = self.conn.cursor()
			self.create_table()
		self.conn = sqlite.connect(dbfile)
		self.cursor = self.conn.cursor()
	def close(self):
		self.cursor.close()
		self.conn.close()
	def create_table(self):
		self.cursor.execute('CREATE TABLE karma(nome VARCHAR(30) PRIMARY KEY, total INTEGER);')
		self.cursor.execute('CREATE TABLE url(nome VARCHAR(30) PRIMARY KEY, total INTEGER);')
		self.cursor.execute('CREATE TABLE slack(nome VARCHAR(30), total INTEGER, data DATE, PRIMARY KEY (data, nome));')
		self.conn.commit()
	def insert_karma(self,nome,total):
		try:
			self.cursor.execute("INSERT INTO karma(nome,total) VALUES ('%s', %d );" % (nome,total))
			self.conn.commit()
			return True
		except:
			#print "Unexpected error:", sys.exc_info()[0]
			return False
	def increment_karma(self,nome):
		if not self.insert_karma(nome,1):
			self.cursor.execute("UPDATE karma SET total = total + 1 where nome = '%s';" % (nome))
			self.conn.commit()
	def decrement_karma(self,nome):
		if not self.insert_karma(nome,-1):
			self.cursor.execute("UPDATE karma SET total = total - 1 where nome = '%s';" % (nome))
			self.conn.commit()
	def insert_url(self,nome,total):
		try:
			self.cursor.execute("INSERT INTO url(nome,total) VALUES ('%s', %d );" % (nome,total))
			self.conn.commit()
			return True
		except:
			return False
	def increment_url(self,nome):
		if not self.insert_url(nome,1):
			self.cursor.execute("UPDATE url SET total = total + 1 where nome = '%s';" % (nome))
			self.conn.commit()
	def insert_slack(self,nome,total):
		try:
			self.cursor.execute("INSERT INTO slack(nome,total,data) VALUES ('%s', %d, '%s' );" % (nome,total,time.strftime("%Y-%m-%d", time.localtime())))
			self.conn.commit()
			return True
		except:
			return False
	def increment_slack(self,nome,total):
		if not self.insert_slack(nome,total):
			self.cursor.execute("UPDATE slack SET total = total + %d where nome = '%s' and data = '%s' ;" % (total,nome,time.strftime("%Y-%m-%d", time.localtime())))
			self.conn.commit()
	def get_karmas_count(self):
		self.cursor.execute('SELECT nome,total FROM karma order by total desc')
		karmas = ''
		for linha in self.cursor:
			if len(karmas) == 0:
				karmas = (linha[0]) + ' = ' + str(linha[1])
			else:
				karmas = karmas + ', ' + (linha[0]) + ' = ' + str(linha[1])
		return karmas
	def get_karmas(self):
		self.cursor.execute('SELECT nome FROM karma order by total desc')
		karmas = ''
		for linha in self.cursor:
			if len(karmas) == 0:
				karmas = (linha[0])
			else:	
				karmas = karmas + ', ' + (linha[0])
		return karmas
	def get_karma(self, nome):
		self.cursor.execute("SELECT total FROM karma where nome = '%s'" % (nome))
		for linha in self.cursor:
				return (linha[0])
	def get_urls_count(self):
		self.cursor.execute('SELECT nome,total FROM url order by total desc')
		urls = ''
		for linha in self.cursor:
			if len(urls) == 0:
				urls = (linha[0]) + ' = ' + str(linha[1])
			else:
				urls = urls + ', ' + (linha[0]) + ' = ' + str(linha[1])
		return urls
	def get_slacker_count(self):
		self.cursor.execute("SELECT nome,total FROM slack where data = '%s' order by total desc" % (time.strftime("%Y-%m-%d", time.localtime())))
		slackers = ''
		for linha in self.cursor:
			if len(slackers) == 0:
				slackers = (linha[0]) + ' = ' + str(linha[1])
			else:
				slackers = slackers + ', ' + (linha[0]) + ' = ' + str(linha[1])
		return slackers


class html:
	def __init__(self, url):
		self.url = url
		self.feed = None
		self.headers = {
	      'User-Agent' : 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.10)',
   	   'Accept-Language' : 'pt-br,en-us,en',
      	'Accept-Charset' : 'utf-8,ISO-8859-1'
	   }
	def title(self):
		self.feed = self.get_data()
		title_pattern = re.compile(r"<[Tt][Ii][Tt][Ll][Ee]>(.*?)</[Tt][Ii][Tt][Ll][Ee]>", re.UNICODE)
		title_search = title_pattern.search(self.feed)
		if title_search is not None:
			try:
				return "[ "+re.sub("&#?\w+;", "", title_search.group(1) )+" ]"
			except:
				print "Unexpected error:", sys.exc_info()[0]
				return "[ Fail in parse ]"
	def get_data(self):
		try:
			reqObj = urllib2.Request(self.url, None, self.headers)
			urlObj = urllib2.urlopen(reqObj)
			return  urlObj.read(4096).strip().replace("\n","").replace("\r", "")
		except:
			print "Unexpected error:", sys.exc_info()
			return "<title>Fail in get</title>"


banco = db('carcereiro.db')
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((server, 6667))
sock.settimeout(900)
sock.send('NICK %s \r\n' % nick)
sock.send('USER %s \'\' \'\' :%s\r\n' % (nick, 'python'))
sock.send('JOIN %s \r\n' % channel)



while True:
	buffer = sock.recv(2040)
	if not buffer:
		break
	print buffer

	if buffer.find('PING') != -1: 
		sock.send('PONG ' + buffer.split() [1] + '\r\n')

	if re.search(':[!@]help', buffer, re.UNICODE) is not None or re.search(':'+nick+'[ ,:]+help', buffer, re.UNICODE) is not None:
		sendmsg('@karmas, @urls, @slackers\r\n')

	regexp  = re.compile('PRIVMSG.*[: ]([a-z][0-9a-z_\-\.]+)\+\+', re.UNICODE)
	regexm  = re.compile('PRIVMSG.*[: ]([a-z][0-9a-z_\-\.]+)\-\-', re.UNICODE)
	regexk  = re.compile('PRIVMSG.*:karma ([a-z_\-\.]+)', re.UNICODE)
	regexu  = re.compile('PRIVMSG.*[: ]\@urls', re.UNICODE)
	regexs  = re.compile('PRIVMSG.*[: ]\@slackers', re.UNICODE)
	regexks = re.compile('PRIVMSG.*[: ]\@karmas', re.UNICODE)
	regexslack  = re.compile(':([a-zA-Z0-9\_]+)!.* PRIVMSG.* :(.*)$', re.UNICODE)
	pattern_url   = re.compile(':([a-zA-Z0-9\_]+)!.* PRIVMSG .*(http://[^ \t>\n\r]+)', re.UNICODE)
	
	resultp  = regexp.search(buffer)
	resultm  = regexm.search(buffer)
	resultk  = regexk.search(buffer)
	resultu  = regexu.search(buffer)
	results  = regexs.search(buffer)
	resultks = regexks.search(buffer)
	resultslack = regexslack.search(buffer)
	url_search = pattern_url.search(buffer)

	if resultslack is not None:
		var = len(resultslack.group(2)) - 1
		nick = resultslack.group(1)
		banco.increment_slack(nick,var)

	if resultp is not None:
		var = resultp.group(1)
		banco.increment_karma(var)
		sendmsg(var + ' now has ' + str(banco.get_karma(var)) + ' points of karma')
		continue

	if resultm is not None:
		var = resultm.group(1)
		banco.decrement_karma(var)
		sendmsg(var + ' now has ' + str(banco.get_karma(var)) + ' points of karma')
		continue

	if resultk is not None:
		var = resultk.group(1)
		points = banco.get_karma(var)
		if points is not None:
			sendmsg(var + ' have ' + str(points) + ' points of karma')
		else:
			sendmsg(var + ' doesn\'t have any point of karma')
		continue

	if resultks is not None:
		sendmsg('karmas : ' + banco.get_karmas_count())
		continue
	
	if results is not None:
		sendmsg('slackers in chars : ' + banco.get_slacker_count())
		continue

	if resultu is not None:
		sendmsg('users : ' + banco.get_urls_count())
		continue
	
	if url_search is not None:
		try:
			url  = url_search.group(2)
			nick = url_search.group(1)
			print 'url: %r' % (url)
			parser = html(url)
			sendmsg(  parser.title() )
			banco.increment_url( nick )
		except:
			sendmsg('[ Failed ]')
			print url
			print "Unexpected error:", sys.exc_info()[0]

sock.close()
banco.close()
