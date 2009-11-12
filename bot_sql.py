#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import socket
import sys
import urllib2
import os
import time
import traceback
from pysqlite2 import dbapi2 as sqlite

DATA_LIMIT = 262144
DATA_CHUNK = 1024

ENCODING = 'utf-8'
FALLBACK_ENCODING = 'iso-8859-1'

channel = '#masmorra'
nick = 'carcereiro'
server = 'irc.oftc.net' 

def _sendmsg(who, msg): 
    s = 'PRIVMSG '+ who + ' :' + unicode(msg) + '\r\n'
    sock.send(s.encode(ENCODING))

def sendmsg(msg):
    return _sendmsg(channel, msg)

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
				karmas = (linha[0]) + ' = ' + unicode(linha[1])
			else:
				karmas = karmas + ', ' + (linha[0]) + ' = ' + unicode(linha[1])
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
				urls = (linha[0]) + ' = ' + unicode(linha[1])
			else:
				urls = urls + ', ' + (linha[0]) + ' = ' + unicode(linha[1])
		return urls
	def get_slacker_count(self):
		self.cursor.execute("SELECT nome,total FROM slack where data = '%s' order by total desc" % (time.strftime("%Y-%m-%d", time.localtime())))
		slackers = ''
		for linha in self.cursor:
			if len(slackers) == 0:
				slackers = (linha[0]) + ' = ' + unicode(linha[1])
			else:
				slackers = slackers + ', ' + (linha[0]) + ' = ' + unicode(linha[1])
		return slackers


def try_unicode(s, enc_list):
	for e in enc_list:
		try:
			return unicode(s, e)
		except:
			pass

	# no success:
	return unicode(s, enc_list[0], 'replace')

def data_as_unicode(resp, s):
	info = resp.info()
	try:
		ctype,charset = info['Content-Type'].split('charset=')  
	except:
		charset = ENCODING

	return try_unicode(s, [charset, ENCODING, FALLBACK_ENCODING])

class html:
	def __init__(self, url):
		self.url = url
		self.headers = {
	      'User-Agent' : 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.10)',
   	   'Accept-Language' : 'pt-br,en-us,en',
      	'Accept-Charset' : 'utf-8,ISO-8859-1'
	   }
	def title(self):
		reqObj = urllib2.Request(self.url, None, self.headers)
		self.urlObj = urllib2.urlopen(reqObj)
		self.resp_headers = self.urlObj.info()
		print 'headers:',repr(self.resp_headers.items())

		ctype = self.resp_headers.get('content-type', '')
		print 'content type: %r' % (ctype)

		if ctype.startswith('image/'):
			return u"olha, uma imagem!"

		if ctype.startswith('audio/'):
			return u"eu não tenho ouvidos, seu insensível!"

		if 'html' in ctype or 'xml' in ctype:
			title_pattern = re.compile(r"<title[^>]*?>(.*?)< */ *title *>", re.UNICODE|re.MULTILINE|re.DOTALL|re.IGNORECASE)
			data = ''
			while True:
				if len(data) > DATA_LIMIT:
					break

				d = self.urlObj.read(DATA_CHUNK)
				if not d:
					break

				data += d

				udata = data_as_unicode(self.urlObj, data)

				title_search = title_pattern.search(udata)
				if title_search is not None:
					title = title_search.group(1)
					title = title.strip().replace("\n"," ").replace("\r", " ")
					title = re.sub("&#?\w+;", "", title)
					print 'title: ',repr(title)
					return u"[ %s ]" % (title)
			# no title found
			return None

		return u"%s? o que é isso?" % (ctype)


password = sys.argv[1]

banco = db('carcereiro.db')
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((server, 6667))
sock.settimeout(900)

# initially use nick_ (I hope nobody will connect using it :)
sock.send('NICK %s_ \r\n' % nick)
sock.send('USER %s \'\' \'\' :%s\r\n' % (nick, 'python'))

# regain nick, if it is in use
sock.send('NICKSERV REGAIN %s %s\r\n' % (nick, password))

# change to the real nick
sock.send('NICK %s \r\n' % nick)
sock.send('NICKSERV IDENTIFY %s\r\n' % (password))

# join the channel
sock.send('JOIN %s \r\n' % channel)


def do_karma(r):
	var = r.group(1)
	banco.increment_karma(var)
	if var == nick:
		sendmsg('eu sou foda! ' + unicode(banco.get_karma(var)) + ' pontos de karma')
	else:
		sendmsg(var + ' now has ' + unicode(banco.get_karma(var)) + ' points of karma')

def do_slack(r):
	var = len(r.group(2)) - 1
	nick = r.group(1)
	banco.increment_slack(nick,var)
	# continue handling other regexps
	return True


def do_dec_karma(resultm):
	var = resultm.group(1)
	banco.decrement_karma(var)
	if var == nick:
		sendmsg('tenho ' + unicode(banco.get_karma(var)) + ' pontos de karma agora  :(')
	else:
		sendmsg(var + ' now has ' + unicode(banco.get_karma(var)) + ' points of karma')


def do_show_karma(resultk):
	var = resultk.group(1)
	points = banco.get_karma(var)
	if points is not None:
		sendmsg(var + ' have ' + unicode(points) + ' points of karma')
	else:
		sendmsg(var + ' doesn\'t have any point of karma')

def do_dump_karmas(r):
	sendmsg('karmas : ' + banco.get_karmas_count())

def do_slackers(r):
	sendmsg('slackers in chars : ' + banco.get_slacker_count())

def do_urls(r):
	sendmsg('users : ' + banco.get_urls_count())

def do_url(url_search):
	try:
		url  = url_search.group(2).encode('utf-8')
		nick = url_search.group(1)
		print 'url: %r' % (url)
		try:
			parser = html(url)
			t = parser.title()
		except urllib2.URLError,e:
			t = u"ui. erro. o servidor não gosta de mim (%s)" % (str(e))
			traceback.print_exc()
		except Exception,e:
			t = u"acho que algo explodiu aqui. :( -- %s" % (str(e))
			print "Unexpected error:", sys.exc_info()[0]
			traceback.print_exc()

		if not t:
			t = u"não consegui achar o título. desculpa tio  :("

		sendmsg(t)
		banco.increment_url( nick )
	except:
		sendmsg('[ Failed ]')
		print url
		print "Unexpected error:", sys.exc_info()[0]
		traceback.print_exc()

regexes = [
	(':([a-zA-Z0-9\_]+)!.* PRIVMSG.* :(.*)$', do_slack),
	('(?i)PRIVMSG.*[: ](g|google|)wave--', lambda r: sendmsg(u'o Google Wave é uma merda mesmo, todo mundo já sabe') or True),
	('PRIVMSG.*[: ](\w\w+)\+\+', do_karma),
	('PRIVMSG.*[: ](\w\w+)\-\-', do_dec_karma),
	('PRIVMSG.*:karma (\w+)', do_show_karma),
	('PRIVMSG.*[: ]\@karmas', do_dump_karmas),
	('PRIVMSG.*[: ]\@slackers', do_slackers),
	('PRIVMSG.*[: ]\@urls', do_urls),
	('PRIVMSG.*[: ]ronaldo!', lambda r: sendmsg(u'brilha muito nu curintia!')),
	('PRIVMSG.*[: ]curintia!', lambda r: sendmsg(u'brilha muito no ronaldo!')),
	('PRIVMSG.*[: ]coraldo!', lambda r: sendmsg(u'brilha muito no ronintia!')),
	('PRIVMSG.*[: ]jip(e|inho) +tomb(a|ou)', lambda r: sendmsg(u'nao fala em jipe tombar!')),
	('PRIVMSG.*[: ](bot|carcereiro) burro', lambda r: sendmsg(":'(")),
	(':([a-zA-Z0-9\_]+)!.* PRIVMSG .*?(https?://[^ \t>\n\r]+)', do_url),
	('PRIVMSG.*[: ](carcereiro|carcy)', lambda r: sendmsg('eu?')),
]

compiled_res = []
# compile all regexes:
for e,f in regexes:
	cr = re.compile(e, re.UNICODE)
	compiled_res.append( (cr, f) )

while True:
	buffer = sock.recv(2040)
	if not buffer:
		break
	print buffer

	if buffer.find('PING') != -1: 
		sock.send('PONG ' + buffer.split() [1] + '\r\n')

	if re.search(':[!@]help', buffer, re.UNICODE) is not None or re.search(':'+nick+'[ ,:]+help', buffer, re.UNICODE) is not None:
		sendmsg('@karmas, @urls, @slackers\r\n')

	msg = try_unicode(buffer, [ENCODING, FALLBACK_ENCODING])

	for exp,fn in compiled_res:
		r = exp.search(msg)
		if r:
			res = fn(r)
			if not res:
				break



sock.close()
banco.close()
