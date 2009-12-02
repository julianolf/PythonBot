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
	sendcmd('PRIVMSG', [who], unicode(msg).encode(ENCODING))

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


password = sys.argv[1]

banco = db('carcereiro.db')
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((server, 6667))
sock.settimeout(900)

# initially use nick_ (I hope nobody will connect using it :)
sendcmd('NICK', ['%s_' % (nick)])
sendcmd('USER', [nick, "''", "''"], 'python')

# regain nick, if it is in use
sendcmd('NICKSERV', ['REGAIN', nick, password])

# change to the real nick
sendcmd('NICK', [nick])
sendcmd('NICKSERV', ['IDENTIFY', password])

# join the channel
sendcmd('JOIN', [channel])


def do_show_karma(resultk):
	var = resultk.group(1)
	points = banco.get_karma(var)
	if points is not None:
		sendmsg(var + ' have ' + unicode(points) + ' points of karma')
	else:
		sendmsg(var + ' doesn\'t have any point of karma')

def do_dump_karmas(r):
	sendmsg('high karmas: ' + banco.get_karmas_count(True))
	sendmsg('low karmas: ' + banco.get_karmas_count(False))

def do_slackers(r):
	sendmsg('slackers in chars : ' + banco.get_slacker_count())

def do_urls(r):
	sendmsg('users : ' + banco.get_urls_count())

def do_url(url_search):
	try:
		url  = url_search.group(2).encode('utf-8')
		nick = url_search.group(1)
		print "*** Getting URL %r ..." % (url)
		print '*** url: %r' % (url)
		try:
			parser = html(url)
			t = parser.title()
		except urllib2.URLError,e:
			t = u"ui. erro. o servidor não gosta de mim (%s)" % (str(e))
			traceback.print_exc()
		except Exception,e:
			t = u"acho que algo explodiu aqui. :( -- %s" % (str(e))
			print "*** Unexpected error:", sys.exc_info()[0]
			traceback.print_exc()

		if not t:
			t = u"não consegui achar o título. desculpa tio  :("

		sendmsg(t)
		banco.increment_url( nick )
	except:
		sendmsg('[ Failed ]')
		print url
		print "*** Unexpected error:", sys.exc_info()[0]
		traceback.print_exc()

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
	if var == nick:
		reply('eu sou foda! ' + unicode(banco.get_karma(var)) + ' pontos de karma')
	else:
		reply(var + ' now has ' + unicode(banco.get_karma(var)) + ' points of karma')

def do_dec_karma(m, r, reply):
	var = r.group(1)
	banco.decrement_karma(var)
	if var == nick:
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
	banco.change_karma(var, amount)
	reply(var + ' now has ' + unicode(banco.get_karma(var)) + ' points of karma')


# list of (regex, function) pairs
# the functions should accept three args: the incoming message, and the regexp match object, and a "reply function"
# to send replies.
# if the handler function return a false value (0, None, False, etc), it will stop the regexp processing
_channel_res = [
	('(.*)', lambda m,r,reply: sys.stdout.write("got channel message: %r, %r\n" % (m, r.groups())) or True ),
	('(.*)', do_slack),

	('\\b(\w(\w|[._-])+)\+\+', do_karma),
	('\\b(\w(\w|[._-])+)\-\-', do_dec_karma),
	('\\b(\w(\w|[._-])+) *(\+|-)= *([0-9]+)', do_karma_sum),
	('''(?i)\\b(g|google|)\.*wave--''', lambda m,r,reply: reply(u'o Google Wave é uma merda mesmo, todo mundo já sabe') or True),
	('^carcereiro[:,] *(.*)', personal_msg_on_channel),

	(u'o carcereiro roubou p[ãa]o na casa do jo[ãa]o', lambda m,r,reply: send_nick_reply(reply, m.sender_nick, u'quem, eu?')),
	('carcereiro|carcy', lambda m,r,reply: reply(u"eu?")),

	('lala', lambda m,r,reply: sys.stdout.write("lala\n") or True),
	('lalala', lambda m,r,reply: sys.stdout.write("lalala\n")),

	('(?i)\\bronaldo!', lambda m,r,reply: reply(u'brilha muito nu curintia!')),
	('(?i)\\bcurintia!', lambda m,r,reply: reply(u'brilha muito no ronaldo!')),
	('(?i)\\bcoraldo!', lambda m,r,reply: reply(u'brilha muito no ronintia!')),
	('^ *tu[ -]*dum[\.!]*$''', lambda m,r,reply: reply(u'PÁ!')),
	(u'(?i)^o* *meu +pai +(é|e)h* +detetive[\.!]*$', lambda m,r,reply: reply(u'mas o teu é despachante')),
	(u'(?i)ningu[ée]m f(a|e)z nada!', lambda m,r,reply: reply(u'ninguém f%sz nada! NA-DA!' % (r.group(1)))),
	('(?i)\\bjip(e|inho) +tomb(a|ou)', lambda m,r,reply: reply(u'nao fala em jipe tombar!')),
	('(?i)\\b(bot|carcereiro) burro', lambda m,r,reply: reply(":'(")),


	('\\b/wb/', lambda m,r,reply: reply(u'eu não tenho acesso ao /wb/, seu insensível!')),
]

channel_res = [(re.compile(r, re.UNICODE), fn) for (r, fn) in _channel_res]



def handle_res(re_list, m, reply_func):
	for r,fn in re_list:
		match = r.search(m.text)
		if match:
			r = fn(m, match, reply_func)
			if not r:
				return r
	return True

def handle_channel_msg(m, reply_func):
	return handle_res(channel_res, m, reply_func)

# list of "personal message" res
# like channel_res, but for (private or nick-prefixed) "personal messages"
_personal_res = [
	('^funciona\?$', lambda m,r,reply: reply("sim!")),
	('burro', lambda m,r,reply: reply(":(")),
	('^ping\?*$', lambda m,r,reply: reply("pong!")),
	(u'^sim[, ]+voc[êe]', lambda m,r,reply: reply(u"eu não!")),
	('(.*)', lambda m,r,reply: reply(u"não entendi")),
]
personal_res = [(re.compile(r, re.UNICODE), fn) for (r, fn) in _personal_res]

def handle_personal_msg(m, reply_func):
	print "***** personal msg received. %r" % (m)
	return handle_res(personal_res, m, reply_func)
	
def handle_privmsg(m):
	print "***** privmsg received: %r" % (m)
	# set additional useful message attributes
	m.target,m.text = m.args

	#FIXME: make only the text part be unicode
	m.target = str(m.target)

	if m.target == channel:
		handle_channel_msg(m, channel_reply_func(channel))
	elif m.target == nick and m.sender_nick:
		handle_personal_msg(m, private_reply_func(m.sender_nick))


def handle_ping(m):
	print "***** got PING: %r" % (m)
	sendcmd('PONG', [], m.args[0])

# handler for each command type. keys are in lower case
cmd_handlers = {
	'privmsg':handle_privmsg,
	'ping':handle_ping,
}

def cmd_received(r):
	groups = r.groups()
	prefix,_,cmd,middle,_,trailing,_ = groups
	args = middle.split()

	if trailing != '':
		a = trailing[1:]
		args.append(a)

	if prefix != '':
		sender = prefix[1:]
	else:
		sender = None

	#FIXME: make only the text part be unicode
	sender = str(sender)
	m = Message(sender, str(cmd), args)
	print '*** cmd received: ', repr(m)

	h = cmd_handlers.get(m.cmd.lower())
	if h:
		h(m)

	# continue handling the legacy regexps
	return True


# regexes for IRC commands:
regexes = [
	('^((:[^ ]* +)?)([a-zA-Z]+) +(([^:][^ ]* +)*)((:.*)?)\r*\n*$', cmd_received),
	('PRIVMSG.*:karma (\w+)', do_show_karma),
	('PRIVMSG.*[: ]\@karmas', do_dump_karmas),
	('PRIVMSG.*[: ]\@slackers', do_slackers),
	('PRIVMSG.*[: ]\@urls', do_urls),
	(':([a-zA-Z0-9\_]+)!.* PRIVMSG .*?(https?://[^ \t>\n\r\x01-\x1f]+)', do_url),
]

compiled_res = []
# compile all regexes:
for e,f in regexes:
	cr = re.compile(e, re.UNICODE)
	compiled_res.append( (cr, f) )


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
	if re.search(':[!@]help', line, re.UNICODE) is not None or re.search(':'+nick+'[ ,:]+help', line, re.UNICODE) is not None:
		sendmsg('@karmas, @urls, @slackers\r\n')

	msg = try_unicode(line, [ENCODING, FALLBACK_ENCODING])

	for exp,fn in compiled_res:
		r = exp.search(msg)
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
