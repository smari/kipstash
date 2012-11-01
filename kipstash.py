#1/usr/bin/python

from Crypto.PublicKey import RSA
import ConfigParser
import os, sys
import simplejson as json
import bsdiff
import _fam
import getopt
import socket, ssl
import pprint

DEFAULT_SERVER_PORT = 3477
DEFAULT_KEY_SIZE = 4097

def keys_generate(size=DEFAULT_KEY_SIZE):
	keypair = RSA.generate(size)
	privkey = keypair.__getstate__()
	pubkey = keypair.publickey().__getstate__()
	privatekey = json.dumps(privkey).encode("base64")
	publickey = json.dumps(pubkey).encode("base64")
	return (privatekey, publickey)


def read_keyblock(text):
	j = text.decode("base64")
	state = json.loads(j)
	state["e"] = long(state["e"])
	return state


def get_pubkey(publickey):
	state = read_keyblock(publickey)
	rsa = RSA.construct((state["n"], state["e"]))
	return rsa

def get_privkey(privatekey):
	state = read_keyblock(privatekey)
	rsa = RSA.construct((state["n"], state["e"]))
	rsa.__setstate__(state)
	return rsa

def config_load(filename):
	config = ConfigParser.ConfigParser()
	try:
		config.read(filename)
	except:
		pass

	return config

def config_save(config, filename):
	config.write(open(filename, "w"))

def dirmap_load(filename):
	pass

def dirmap_save(filename):
	pass

def filemap_load(filename):
	pass

def filemap_save(filename):
	pass


def block_write():
	
	pass


def block_parse(blocktext):
	pass


def server_init(dir="~/.kipstash"):
	dir = os.path.expanduser(dir)
	
	if not os.path.exists(dir):
		print "Initializing server for the first time ever."
		os.mkdir(dir, 0700)

	if not os.path.exists(dir+"/server.pub"):
		print "Generating server keys..."
		server_pubkey = open(dir+"/server.pub", "w")
		server_privkey = open(dir+"/server.sec", "w")
		priv, pub = keys_generate()
		server_pubkey.write(pub)
		server_privkey.write(priv)
		server_pubkey.close()
		server_privkey.close()
		priv = get_privkey(priv)
		pub = get_pubkey(pub)
	else:
		priv = get_privkey(open(dir+"/server.sec").read())
		pub = get_pubkey(open(dir+"/server.pub").read())
		print "Server keys loaded..."

	config = config_load(dir+"/kipstash.cfg")

	return (config, priv, pub)	


def client_init(dir="~/.kipstash"):
	dir = os.path.expanduser(dir)
	
	if not os.path.exists(dir):
		print "Initializing client for the first time ever. Generating keys and such."
		os.mkdir(dir, 0700)
		client_pubkey = open(dir+"/client.pub", "w")
		client_privkey = open(dir+"/client.sec", "w")
		priv, pub = keys_generate()
		client_pubkey.write(pub)
		client_privkey.write(priv)
		client_pubkey.close()
		client_privkey.close()
		priv = get_privkey(priv)
		pub = get_pubkey(pub)
	else:
		priv = get_privkey(open(dir+"/client.sec").read())
		pub = get_pubkey(open(dir+"/client.pub").read())

	dirmap = dirmap_load(dir+"/dir.map")
	filemap = filemap_load(dir+"/file.map")
	config = config_load(dir+"/kipstash.cfg")

	return (config, dirmap, filemap, priv, pub)
		

def diff(file):
	# bsdiff.Diff("foo", "boo")
	pass


def patch(file):
	# bsdiff.Patch("foo", 3, [(3, 0, -1)], '\xfc\x00\x00', '')
	pass


class DirectoryMonitor:
	def __init__(self, connection):
		self.fam = _fam.open()
		self.mon = None
		self.connection = connection

	def start(self, dir):
		self.mon = self.fam.monitorDirectory(dir, None)

	def stop(self):
		self.mon.cancelMonitor()
		self.fam.close()

	def process(self):
		if self.mon == None: return

		while self.fam.pending():
			ev = self.fam.nextEvent()
			self.processevent(ev)

	def processevent(self, event):
		if event.userData:
			print event.userData,
		print event.requestID,
		print event.filename, event.code2str()


class ClientConnection:
	def __init__(self, server):
		self.server = server
		if self.server.find(":") != -1:
			self.server_host, self.server_port = self.server.split(":")
		else:
			self.server_host = self.server
			self.server_port = DEFAULT_SERVER_PORT

		print "Connecting to server..."
		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.ssl_sock = ssl.wrap_socket(self.socket) # , ca_certs="/etc/ca_certs_file", cert_reqs=ssl.CERT_OPTIONAL)
			self.ssl_sock.connect((self.server_host, self.server_port))

			print repr(self.ssl_sock.getpeername())
			print self.ssl_sock.cipher()
			print pprint.pformat(self.ssl_sock.getpeercert())
		except socket.error, e:
			print "Error: %s " % e.strerror
			sys.exit(0)
		except Exception, e:
			print e
			sys.exit(0)

	def read(self):
		return self.ssl_sock.read()

	def close(self):
		self.ssl_sock.close()



def client():
	print "Client starting..."
	(config, dirmap, filemap, priv, pub) = client_init()
	
	try:
		server = config.get("client", "server")
	except:
		print "No servers configured. Quitting."
		sys.exit(0)
	print "Connecting to server %s" % server
	con = ClientConnection(server)

	d = DirectoryMonitor(con)
	try:
		share_dir = config.get("client", "share_dir")
	except:
		print "No shares configured. Quitting."
		sys.exit(0)
	print "Sharing from %s" % share_dir
	d.start(share_dir)

	while True:
		d.process()


def server_clientmanage(stream):
	data = stream.read()
	# null data means the client is finished with us
	while data:
		print "Data: '%s'" % data
		# if not do_something(connstream, data):
		#	# we'll assume do_something returns False
		#	# when we're finished with client
		#	break
		data = stream.read()


def server():
	print "Server starting..."
	(config, priv, pub) = server_init()

	try:
		hostname = config.get("server", "hostname")
		port = config.getint("server", "port")
		server_certfile = config.get("server", "ssl_cert")
		server_keyfile = config.get("server", "ssl_key")
	except:
		print "Server hostname and port must be configured."
		sys.exit(0)

	bindsocket = socket.socket()
	bindsocket.bind((hostname, port))
	bindsocket.listen(5)

	print "Server listening on %s:%d" % (hostname, port)

	while True:
		newsocket, fromaddr = bindsocket.accept()
		print "Client connected from %s..." % fromaddr
		connstream = ssl.wrap_socket(newsocket, server_side=True, 
				certfile=server_certfile, keyfile=server_keyfile,
				ssl_version=ssl.PROTOCOL_TLSv1)
		print "SSL handshake complete."
		try:
			server_clientmanage(connstream)
		finally:
			connstream.shutdown(socket.SHUT_RDWR)
			connstream.close()

	print "Server exiting..."


if __name__ == "__main__":
	servermode = False

	optlist, args = getopt.getopt(sys.argv[1:], 's')
	for arg, value in optlist:
		if arg == "-s":
			servermode = True

	if servermode:
		server()
	else:
		client()
