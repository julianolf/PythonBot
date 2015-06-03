#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import socket
import sys
import urllib2
import os
import time
import traceback
import json
from random import choice
from sqlite3 import dbapi2 as sqlite
from datetime import datetime

if len(sys.argv) < 4:
	print "usage: bot_sql.py <nick> <nick_password> <channel> [channel2, ...]"
	sys.exit()

DATA_LIMIT = 262144
DATA_CHUNK = 1024

ENCODING = 'utf-8'
FALLBACK_ENCODING = 'iso-8859-1'

NICK = None
SERVER = 'irc.freenode.net'

nick_list = []

def sendcmd(cmd, middle, trail=None):
	m = '%s ' % (cmd)
	for a in middle:
		m += '%s ' % (a)
	if trail is not None:
		m += ':%s' % (trail)
	m += '\r\n'
	print "*** sending data: %r" % (m)
	sock.send(m)

def _sendmsg(who, msg): 
	if isinstance(msg, str):
		msg = unicode(msg, ENCODING)
	sendcmd('PRIVMSG', [who], unicode(msg).encode(ENCODING))

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
		self.cursor.execute('CREATE TABLE link(url VARCHAR(255) PRIMARY KEY, title VARCHAR(255), nick VARCHAR(30), data DATE);')
		self.conn.commit()
	def insert_karma(self,nome,total):
		try:
			self.cursor.execute("INSERT INTO karma(nome,total) VALUES ('%s', %d );" % (nome,total))
			self.conn.commit()
			return True
		except:
			return False
	def change_karma(self,nome,amount):
		if not self.insert_karma(nome,amount):
			self.cursor.execute("UPDATE karma SET total = total + (%d) where nome = '%s';" % (amount, nome))
			self.conn.commit()
	def increment_karma(self,nome):
		return self.change_karma(nome, 1)
	def decrement_karma(self,nome):
		return self.change_karma(nome, -1)
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
	def insert_link(self, url, title, nick):
		try:
			sql_insert = "INSERT INTO link(url,title,nick,data) VALUES ('%s','%s','%s','%s');" % (url,title,nick,time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
			self.cursor.execute(sql_insert)
			self.conn.commit()
			print "*** New link registered ***"
			print sql_insert
		except:
			return False
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
	def get_karmas_count(self, desc=True, max_len=400):
		q = 'SELECT nome,total FROM karma order by total'
		if desc:
			q += ' desc'
		self.cursor.execute(q)
		karmas = ''
		for linha in self.cursor:
			item = (linha[0]) + ' = ' + unicode(linha[1])
			if len(karmas) == 0:
				append = item
			else:
				append = ', ' + item
			if len(karmas) + len(append) > max_len:
				break
			karmas += append
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
	def get_links(self):
		self.cursor.execute("SELECT * FROM link ORDER BY data DESC LIMIT 20;")
		links = []
		for line in self.cursor:
			link = { 'url':line[0], 'title':line[1], 'nick':line[2], 'data':line[3] }
			links.append(link)
		print "*** Recovered links ***"
		print links
		return links


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
		print '*** headers:',repr(self.resp_headers.items())

		ctype = self.resp_headers.get('content-type', '')
		print '*** content type: %r' % (ctype)

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
					print '*** title: ',repr(title)
					return u"[ %s ]" % (title)
			# no title found
			return None

		return u"%s? o que é isso?" % (ctype)


NICK = sys.argv[1]
password = sys.argv[2]
CHANNELS = sys.argv[3:]

banco = db('bot.db')
#sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
#sock.connect((SERVER, 6667))
sock = socket.create_connection( ( SERVER, 6667) )
sock.settimeout(900)

# initially use nick_ (I hope nobody will connect using it :)
sendcmd('NICK', ['%s_' % (NICK)])
sendcmd('USER', [NICK, "''", "''"], 'python')

# regain nick, if it is in use
sendcmd('NICKSERV', ['REGAIN', NICK, password])

# change to the real nick
sendcmd('NICK', [NICK])
sendcmd('NICKSERV', ['IDENTIFY', password])

# join the channel
for c in CHANNELS:
	sendcmd('JOIN', [c])

sender_re = re.compile('([^!@]+)((![^!@]+)?)((@[^!@]+)?)')

class Message:
	def __init__(self, sender, cmd, args):
		self.sender = sender
		self.cmd = cmd
		self.args = args

		self.sender_nick = self.sender_user = self.sender_host = None
		if self.sender is not None:
			m = sender_re.match(self.sender)
			if not m:
				print "***** sender regexp doesn't match?"
				self.sender_nick = self.sender
			else:
				self.sender_nick = m.group(1)
				self.sender_user = m.group(2).lstrip('!')
				self.sender_host = m.group(4).lstrip('@')

	def __repr__(self):
		return '<message: cmd %r from [%r]![%r]@[%r]. args: %r' % (self.cmd, self.sender_nick, self.sender_user, self.sender_host, self.args)


### helper functions for replying to messages:

def send_channel_msg(channel, msg):
	_sendmsg(channel, msg)

def channel_reply_func(channel):
	return lambda msg: send_channel_msg(channel, msg)

def send_nick_reply(orig_reply_func, nick, msg):
	"""send a "nick:" prefixed message"""
	orig_reply_func(u'%s: %s' % (nick, msg))

def nick_reply_func(orig_reply_func, nick):
	"""Create a nick-reply reply function"""
	return lambda msg: send_nick_reply(orig_reply_func, nick, msg)


def send_private_msg(nick, msg):
	"""Send a private message to a nickname"""
	_sendmsg(nick, msg)

def private_reply_func(nick):
	"""Generate a private-message reply func"""
	return lambda msg: send_private_msg(nick, msg)


### channel-message handlers:

def do_slack(m, r, reply):
	var = len(m.text)
	nick = m.sender_nick
	banco.increment_slack(nick,var)

	# continue handling other regexps
	return True


def personal_msg_on_channel(m, r, reply):
	"""Handle nick-prefixed messages on channel like private messages,
	but reply using a nick prefix on the channel
	"""
	m.text = r.group(1)
	return handle_personal_msg(m, nick_reply_func(reply, m.sender_nick))


def do_karma(m, r, reply):
	var = r.group(1)
	if m.sender_nick == var:
		send_nick_reply(reply, m.sender_nick, "convencido!")
		return
	banco.increment_karma(var)
	if var == NICK:
		reply('eu sou foda! ' + unicode(banco.get_karma(var)) + ' pontos de karma')
	else:
		reply(var + ' now has ' + unicode(banco.get_karma(var)) + ' points of karma')

def do_dec_karma(m, r, reply):
	var = r.group(1)
	if m.sender_nick == var:
		send_nick_reply(reply, m.sender_nick, u"tadinho... vem cá e me dá um abraço!")
	banco.decrement_karma(var)
	if var == NICK:
		reply('tenho ' + unicode(banco.get_karma(var)) + ' pontos de karma agora  :(')
	else:
		reply(var + ' now has ' + unicode(banco.get_karma(var)) + ' points of karma')

def do_karma_sum(m, r, reply):
	var,_,sign,amount = r.groups()
	amount = int(amount)
	if amount > 20:
		reply(u'%d pontos de uma vez? tá doido!?' % (amount))
		return
	if amount > 1:
		reply(u'%d pontos de uma vez é demais' % (amount))
		return
	if sign == '-':
		amount = -amount
	if m.sender_nick == var and amount > 0:
		send_nick_reply(reply, m.sender_nick, "convencido!")
		return
	if m.sender_nick == var and amount < 0:
		send_nick_reply(reply, m.sender_nick, u"tadinho... vem cá e me dá um abraço!")
	banco.change_karma(var, amount)
	reply(var + ' now has ' + unicode(banco.get_karma(var)) + ' points of karma')

def do_url(m, r, reply):
	try:
		url  = r.group(1).encode('utf-8')
		nick = m.sender_nick
		print "*** Getting URL %r ..." % (url)
		print '*** url: %r' % (url)
		try:
			parser = html(url)
			t = parser.title()
		except urllib2.URLError,e:
			t = u"erro no trem de bits! (%s)" % (str(e))
			traceback.print_exc()
		except Exception,e:
			t = u"acho que algo explodiu aqui. :( -- %s" % (str(e))
			print "*** Unexpected error:", sys.exc_info()[0]
			traceback.print_exc()

		if not t:
			t = u"não consegui achar o título. desculpa tio  :("

		reply(t)
		banco.increment_url( nick )
		banco.insert_link( url, t, nick )
	except:
		reply('[ Failed ]')
		print url
		print "*** Unexpected error:", sys.exc_info()[0]
		traceback.print_exc()

def do_links(m, r, reply):
	try:
		print "*** Getting URL list..."
		nick = m.sender_nick
		links = banco.get_links()
		if len(links) > 0:
			for link in links:
				send_private_msg(nick, ("%s [%s] by %s at %s \r\n" % (link['title'], link['url'], link['nick'], link['data'])))
		else:
			send_private_msg(nick, 'Nao encontrei nenhum link.')
	except:
		reply(' Faio :(')
		print "*** Unexpected error: ", sys.exc_info()[0]
		traceback.print_exc()

def do_show_karma(m, r, reply):
	var = r.group(1)
	points = banco.get_karma(var)
	if points is not None:
		reply(var + ' have ' + unicode(points) + ' points of karma')
	else:
		reply(var + " doesn't have any point of karma")

def do_dump_karmas(m, r, reply):
	reply('high karmas: ' + banco.get_karmas_count(True))
	reply('low karmas: ' + banco.get_karmas_count(False))

def do_slackers(m, r, reply):
	reply('slackers in chars : ' + banco.get_slacker_count())

def do_urls(m, r, reply):
	reply('users : ' + banco.get_urls_count())

def do_zodiac(m, r, reply):
	wished = r.group(1)

	# list of zodiacs and a regular expression matching its names respectively
	# this will be used to identify what zodiac user is looking for
	zodiac_table = {
		u'\u00c1ries':       u'[A\u00c1a\u00e1]ries',
		u'Touro':            u'[Tt]ouro',
		u'G\u00eameos':      u'[Gg][\u00eae]meos',
		u'C\u00e2ncer':      u'[Cc][\u00e2a]ncer',
		u'Le\u00e3o':        u'[Ll]e[\u00e3a]o',
		u'Virgem':           u'[Vv]irgem',
		u'Libra':            u'[Ll]ibra',
		u'Escorpi\u00e3o':   u'[Ee]scorpi[\u00e3a]o',
		u'Sagit\u00e1rio':   u'[Ss]agit[\u00e1a]rio',
		u'Capric\u00f3rnio': u'[Cc]apric[\u00f3o]rnio',
		u'Aqu\u00e1rio':     u'[Aa]qu[\u00e1a]rio',
		u'Peixes':           u'[Pp]eixes'
	}

	# the horoscopo API service provides daily information about zodiac
	url = 'http://developers.agenciaideias.com.br/horoscopo/json'
	req = urllib2.Request(url)
	try:
		res = urllib2.urlopen(req)
	except urllib2.HTTPError as httpe:
		print 'The server could not fulfill the request'
		print 'Error code: ', httpe.code
		reply(u'Ta nublado hoje, nada de hor\u00f3scopo')
	except urllib2.URLError as urle:
		print 'Failed to reach a server'
		print 'Reason: ', urle.reason
		reply(u'Ta nublado hoje, nada de hor\u00f3scopo')
	else:
		data = res.read()
		if data:
			# try decode data received from horoscopo service
			info = json.loads(data)
			if (info and 'signos' in info):
				wish = None
				for zodiac_name, zodiac_regex in zodiac_table.iteritems():
					if re.match(zodiac_regex, wished):
						wish = zodiac_name
						break
				if not wish:
					reply(wished + u' n\u00e3o consta nos meus mapas astrais')
				else:
					msg = 'Os astros parecem confusos, e eu mais ainda'
					for zodiac in info['signos']:
						if zodiac['nome'] == wish:
							msg = zodiac['msg'].replace('\r', '').replace('\n', '').replace('\t', '')
							break
					reply(msg)

def do_help(m, r, reply):
	reply('commands: @karma <name>, @karmas, @urls, @links, @slackers, @zodiac <name>')


## regexp-list handling:
def handle_res(re_list, m, reply_func):
	try:
		#print '**** text: %r' % (m.text)
		for r,fn in re_list:
			#print '**** checking for pattern: %r' % (r.pattern)
			match = r.search(m.text)
			if match:
				#print '*** pattern match'
				r = fn(m, match, reply_func)
				if not r:
					return r
		return True
	except Exception,e:
		reply_func(u"acho que algo explodiu aqui. :( -- %s" % (str(e)))
		traceback.print_exc()
		

def include(l):
	"""Used to insert a list inside another one

	Just generates a regexp that calls handle_res for the specified list.
	"""
	return ('', lambda m,r,reply: handle_res(l, m, reply))

def relist(l):
	return [(re.compile(r, re.UNICODE), fn) for (r, fn) in l]
	

def reply_not(reply, msg):
	reply(msg)
	time.sleep(2)
	reply('NOT!')

def list_nicks():
	sendcmd('NAMES', ['#smartgreen'])

# list of (regex, function) pairs
# the functions should accept three args: the incoming message, and the regexp match object, and a "reply function"
# to send replies.
# if the handler function return a false value (0, None, False, etc), it will stop the regexp processing
channel_res = relist([
	('(.*)', lambda m,r,reply: sys.stdout.write("got channel message: %r, %r\n" % (m, r.groups())) or True ),
	('(.*)', do_slack),

	(r'^@*karma (\w+) *$', do_show_karma),
	('[@!]karmas', do_dump_karmas),
	('[@!]slackers', do_slackers),
	('[@!]urls', do_urls),
	('[@!]links', do_links),
	('[@!]help', do_help),

	('(https?://[^ \t>\n\r\x01-\x1f]+)', do_url),

	(u'^[@!]zodiac (\w+) *$', do_zodiac),

	(r'(?i)\b(g|google|)\.*wave--', lambda m,r,reply: reply(u'o Google Wave é uma merda mesmo, todo mundo já sabe') or True),

	(r'\b(\w(\w|[._-])+)\+\+', do_karma),
	(r'\b(\w(\w|[._-])+)\-\-', do_dec_karma),
	(r'\b(\w(\w|[._-])+) *(\+|-)= *([0-9]+)', do_karma_sum),

	(u'o %s roubou p[ãa]o na casa do jo[ãa]o' % NICK, lambda m,r,reply: send_nick_reply(reply, m.sender_nick, u'quem, eu?')),

	('lala', lambda m,r,reply: sys.stdout.write("lala\n") or True),
	('lalala', lambda m,r,reply: sys.stdout.write("lalala\n")),

	(r'(?i)\bsono', lambda m,r,reply: reply(u'sono--')),
	(r'(?i)\bronaldo!', lambda m,r,reply: reply(u'brilha muito nu curintia!')),
	(r'(?i)\bquinino!', lambda m,r,reply: reply(u'brilha muito na balada!')),
	(r'(?i)\bcurintia!', lambda m,r,reply: reply(u'brilha muito no ronaldo!')),
	(r'(?i)\bcoraldo!', lambda m,r,reply: reply(u'brilha muito no ronintia!')),
	(r'^ *tu[ -]*dum[\.!]*$''', lambda m,r,reply: reply(u'PÁ!')),
	(u'(?i)^o* *meu +pai +(é|e)h* +detetive[\.!]*$', lambda m,r,reply: reply(u'mas o teu é despachante')),
	(u'(?i)ningu[ée]m f(a|e)z nada!', lambda m,r,reply: reply(u'ninguém f%sz nada! NA-DA!' % (r.group(1)))),
	(r'(?i)\b(bot|%s) burro' % NICK, lambda m,r,reply: reply(":'(")),
	(u'(?i)\\bo +m[aá]rio\\b', lambda m,r,reply: send_nick_reply(reply, m.sender_nick, u'que mario?')),
	(u'(?i)^(oi|ol[áa])\\b', lambda m,r,reply: send_nick_reply(reply, m.sender_nick, u'oi, tudo bem?')),
	(r'^hey[?!.]*$', lambda m,r,reply: send_nick_reply(reply, m.sender_nick, u'ho!')),
	(r'(?i)\b(nazi|hitler\b)', lambda m,r,reply: send_nick_reply(reply, m.sender_nick, u'Godwin! a discussão acabou, você perdeu.')),
	(u'(?i)^.*japon(ê|e)s.*$', lambda m,r,reply: reply(u'o que tem o rubensm?')),
	(u'(?i)^.*(í|i)ndio.*$', lambda m,r,reply: send_nick_reply(reply, m.sender_nick, u'não fala dos meus amigos índios ou vamos brigar!')),
	(r'(?i)\bnelson', lambda m,r,reply: send_nick_reply(reply, m.sender_nick, u"a-vó-du-nelso-come-nuggets!")),
	(r'(?i)\berva( .*)?', lambda m,r,reply: reply(u'muita gente fala mal da erva, mas a erva... a erva... :O~')),

	('^%s[:, ] *(.*)' % NICK, personal_msg_on_channel),
	(NICK, lambda m,r,reply: reply(u"eu?")),
])



def handle_channel_msg(m, reply_func):
	return handle_res(channel_res, m, reply_func)

def ramdom_nick(sender_nick):
	global nick_list
	nick = 'zé ninguém'
	count = 0
	while count < 5:
		ramdnick = choice(nick_list)
		count += 1
		if ramdnick != sender_nick:
			nick = ramdnick
			break;
	return nick

# list of "personal message" res
# like channel_res, but for (private or nick-prefixed) "personal messages"
personal_res = relist([
	('^funciona\?$', lambda m,r,reply: reply("sim!")),
	(r'^acorda\b', lambda m,r,reply: reply(u"eu tô acordado!")),

	('^@*karma (\w+)$', do_show_karma),
	('^@*karmas', do_dump_karmas),
	('^@*slackers', do_slackers),
	('^@*urls', do_urls),
	('^@*!*help', do_help),

	(r'^oi[?!.]*$', lambda m,r,reply: reply(u'oi. tudo bem?')),
	(r'^(tchau|[a(in)]t[eé]|falou)[!.]*$', lambda m,r,reply: reply(u'inté')),
	(r'^obrigado[!.]*$', lambda m,r,reply: reply(u'disponha')),
	(u'(é|e) ou n(ã|a)o (é|e)\?$', lambda m,r,reply: reply(u'se você está dizendo...')),
	(r'\bhey[?!.]*$', lambda m,r,reply: reply(u'ho!')),
	(u'^(tudo|td) bem[.,]* e* *(vc|voc[eê])[?!.]*$', lambda m,r,reply: reply(u'tudo bem também')),
	(r'\b(tudo|td) bem\?$', lambda m,r,reply: reply(u'tudo bem. e você?')),
	(r'\btudo bem[.!]*$', lambda m,r,reply: reply(u'que bom, então')),
	(r'\bbom dia[.?!]*$', lambda m,r,reply: reply(u'bom dia :)')),

	(r'\bgrosso[!]*$', lambda m,r,reply: reply(u':~')),
	('burro', lambda m,r,reply: reply(":(")),
	(u'o que voc[êe] (acha|me diria) do cleitonalmeida\?', lambda m,r,reply: reply('um tremendo de um safado!')),
	(r'[cC]achorro[!\?\.]?$', lambda m,r,reply: reply(u'cachorro? eu não sou cachorro não!')),
	(u'parab[ée]ns[!]*$', lambda m,r,reply: reply("obrigado :)")),
	(u'^voc(ê|e) (é|e) o cara(!)*$', lambda m,r,reply: reply("eu sou o cara!")),
	('^ping\?*$', lambda m,r,reply: reply("pong!")),
	(u'^sim[, ]+voc[êe]', lambda m,r,reply: reply(u"eu não!")),
	(u'^ent[ãa]o quem foi\?$', lambda m,r,reply: reply(u"foi o %s!" % (ramdom_nick(m.sender_nick)))),
	(u'^eu n[ãa]o!$', lambda m,r,reply: reply(u"então quem foi?")),
	(r'^hadouken!?$', lambda m,r,reply: reply(u"shoryuken!")),
	(r'^sonic boom!?$', lambda m,r,reply: reply(u"tatsumaki senpuukyaku!")),

	(r':(\*+)', lambda m,r,reply: reply(u':%s' % (r.group(1)))),
	(r'\bte (amo|adoro|odeio)', lambda m,r,reply: reply(u'eu também te %s!' % (r.group(1)))),
	(r'\bi( )?m your father$', lambda m,r,reply: reply(u'NOOOOOOOOOOOO!')),
	(u'j[áa] pago(u)?\?$', lambda m,r,reply: reply(u'já pagay')),
	(u'me d[aá] um abra[cç]o\?$', lambda m,r,reply: reply(u'ô pobrezinho, vem ki!')),
	(u'((([Tt]oca|[Bb]ate) aqui )|([Nn][oó]is ))?o/$', lambda m,r,reply: reply(u'\o')),
	(u'diferença entre o? [Ll]utero e o? [Kk]ant\?$', lambda m,r,reply: reply(u'um é iluminista, o outro protestante')),
	(u'que matinho [eé] esse\?$', lambda m,r,reply: reply(u'bateu uma onda fooooorte')),
	(u'[Qq]ue horas ([eé]|s[aã]o)\??$', lambda m,r,reply: reply(datetime.now().time().strftime('%X'))),
	('(.*)', lambda m,r,reply: reply(u"não entendi")),
])

def handle_personal_msg(m, reply_func):
	print "***** personal msg received. %r" % (m)
	return handle_res(personal_res, m, reply_func)
	

#### command handlers:

def handle_privmsg(m):
	print "***** privmsg received: %r" % (m)
	m.target,text = m.args

	# set additional useful message attributes
	m.text = try_unicode(text, [ENCODING, FALLBACK_ENCODING])

	if m.target in CHANNELS:
		handle_channel_msg(m, channel_reply_func(m.target))
	elif m.target == NICK and m.sender_nick:
		handle_personal_msg(m, private_reply_func(m.sender_nick))


def handle_ping(m):
	print "***** got PING: %r" % (m)
	sendcmd('PONG', [], m.args[0])

def channel_mode_add_o(m):
	print '* adding operator flag on channel'
	m.op_who = m.args[2]
	print '* adding operator flag to: %s' % (m.op_who)
	if m.op_who == NICK:
		send_channel_msg(m.mode_target, u"eu tenho a força!")
	else:
		send_channel_msg(m.mode_target, u"%s: me dá op, tio!" % (m.op_who))

def channel_mode(m):
	print '* channel mode command'
	m.flag = m.args[1]
	print '* channel mode flag: %s' % (m.flag)
	if m.flag == '+o':
		return channel_mode_add_o(m)
	
def handle_mode(m):
	print '* mode command received'
	m.mode_target = m.args[0]
	print '* mode target: %s' % (m.mode_target)
	if m.mode_target.startswith('#'):
		return channel_mode(m)
		
def handle_join(m):
	m.join_target = None
	if m.args[0].startswith('#'):
		m.join_target = m.args[0]
	if m.sender_nick != NICK:
		global nick_list
		nick_list.append(m.sender_nick)
		if m.sender_nick in ('cleitonalmeida', 'calmeida'):
			send_channel_msg(m.join_target, u"%s: Bom dia Cleitinhoooo!" % (m.sender_nick))
		elif m.sender_nick in ('hcassilha', 'harison', 'agaharison'):
			send_channel_msg(m.join_target, u"%s: Grande aga-arison!" % (m.sender_nick))
		else:
			send_channel_msg(m.join_target, u"%s: oi!" % (m.sender_nick))
	else:
		list_nicks()

def handle_part(m):
	m.join_target = None
	if m.args[0].startswith('#'):
		m.join_target = m.args[0]
	if m.sender_nick != NICK:
		global nick_list
		nick_list.remove(m.sender_nick)

def handle_names(m):
	global nick_list
	print '* names command received'
	nicks = m.args.pop().split()
	nick_list = [re.sub('[+@]', '', item) for item in nicks]
	nick_list.remove(NICK)

# handler for each command type. keys are in lower case
cmd_handlers = {
	'privmsg':handle_privmsg,
	'ping':handle_ping,
	'mode':handle_mode,
	'join':handle_join,
	'part':handle_part,
	'353':handle_names,
}



### general IRC message handler:
def cmd_received(r):
	groups = r.groups()
	prefix,_,cmd,middle,_,trailing,_ = groups
	args = middle.split()

	if trailing != '':
		a = trailing.lstrip(' ')[1:]
		args.append(a)

	if prefix != '':
		sender = prefix[1:]
	else:
		sender = None

	m = Message(sender, str(cmd), args)
	print '*** cmd received: ', repr(m)

	h = cmd_handlers.get(m.cmd.lower())
	if h:
		h(m)

	# continue handling the legacy regexps
	return True


# regexes for IRC commands:
protocol_res = relist([
	('^((:[^ ]* +)?)([a-zA-Z]+)(( +[^:][^ ]*)*)(( +:.*)?)\r*\n*$', cmd_received),
	('^((:[^ ]* +)?)(353+)(( +[^:][^ ]*)*)(( +:.*)?)\r*\n*$', cmd_received),
])


newline = re.compile('\r*\n')
def readlines(sock):
	buf = ''
	while True:
		data = sock.recv(2040)
		if not data:
			print "**** no returned data. EOF?"
			break
		print '* raw data: ',repr(data)
		buf += data
		while newline.search(buf):
			line,rest = newline.split(buf, 1)
			print "** line: %r" % (line)
			print "** rest: %r" % (rest)
			yield line
			buf = rest

for line in readlines(sock):
	for exp,fn in protocol_res:
		r = exp.search(line)
		if r:
			try:
				res = fn(r)
				if not res:
					break
			except Exception,e:
				print "***** Message handler error: "
				traceback.print_exc()
				



sock.close()
banco.close()
