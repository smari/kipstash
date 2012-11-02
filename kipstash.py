#!/usr/bin/python

from Crypto.PublicKey import RSA
import ConfigParser
import os, sys
import simplejson as json
import bsdiff
import _fam
import getopt
import socket, ssl
import pprint
import hashlib
import random

DEFAULT_SERVER_PORT = 3477
DEFAULT_KEY_SIZE = 4097
	

def hash(filename, rand=False):
	# if rand==True, then add 2000 random characters to the end of the file before hashing.
	# For generating FIDHs.
	h = hashlib.sha512()
	try: fh = open(filename)
	except: return ""
	h.update(fh.read())
	if rand:
		h.update("::" + "".join(["".join(random.sample("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4)) for x in range(500)]))
	return h.hexdigest()


def hash_string(string):
	h = hashlib.sha512()
	h.update(string)
	return h.hexdigest()


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


def file_info(filename):
	s = os.stat(filename)
	hv = hash(filename)
	return {"mode": s.st_mode, "size": s.st_size, "atime": s.st_atime, "mtime": s.st_mtime, "ctime": s.st_ctime, "hash": hv}


def filemap_verify(filemap, dirmap, connection):
	if filemap == {}:
		return True
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


def diff(file):
	# bsdiff.Diff("foo", "boo")
	pass


def patch(file):
	# bsdiff.Patch("foo", 3, [(3, 0, -1)], '\xfc\x00\x00', '')
	pass


class DirectoryMonitor:
	def __init__(self, client):
		self.fam = _fam.open()
		self.mon = None
		self.client = client

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
		if event.code2str() == "created":
			pass			

		if event.code2str() == "changed":
			pass #client.block_file_send(event.filename)

			# self.connection.write("CHANGE EVENT ON %s\n" % event.filename)


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

	def write(self, data):
		return self.ssl_sock.write(data)

	def read(self):
		return self.ssl_sock.read()

	def close(self):
		self.ssl_sock.close()


class KipClient:
	def __init__(self):
		print "Client starting..."
		self.client_init()
	
		try:
			server = self.config.get("client", "server")
		except:
			print "No servers configured. Quitting."
			sys.exit(0)
		print "Connecting to server %s" % server
		con = ClientConnection(server)
		self.connection = con

		self.dirmon = DirectoryMonitor(con)
		try:
			share_dir = self.config.get("client", "share_dir")
		except Exception, e:
			print "No shares configured. Quitting."
			sys.exit(0)

		print "Sharing from %s" % share_dir
		self.share_add(share_dir)
		self.dirmon.start(share_dir)

		self.start()

	def start(self):
		while True:
			self.dirmon.process()
			self.block_receive()

	def block_receive(self):
		pass

	def block_file_send(self, filename, fidh):
		fh = open(filename)
		contents = fh.read()
		crypted = self.pub.encrypt(contents, None)[0].encode("base64")
		block = {"fidh": fidh, "payload": crypted}
		hv = hash_string(json.dumps(block))
		signature = self.priv.sign(hv, None)
		block["sig"] = signature
		self.block_send(block)

	def block_delta_send(self, filename):
		pass

	def block_share_send(self, directory):
		pass

	def block_send(self, cryptedblock):
		return self.connection.write(json.dumps(cryptedblock))

	def client_init(self, dir="~/.kipstash"):
		dir = os.path.expanduser(dir)
		self.workingdir = dir
	
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
			self.priv = get_privkey(priv)
			selfpub = get_pubkey(pub)
		else:
			self.priv = get_privkey(open(dir+"/client.sec").read())
			self.pub = get_pubkey(open(dir+"/client.pub").read())
	
		self.dirmap_load()
		self.filemap_load()
		self.config = config_load(dir+"/kipstash.cfg")
		self.config.set("client", "workingdir", dir)

	def dirmap_load(self):
		try:
			fh = open(self.workingdir+"/dir.map")
			map = json.loads(fh.read())
			fh.close()
			print "Directory map loaded. %d shares." % len(map)
		except Exception, e:
			print "Error loading directory map: ", e
			map = {}

		self.dirmap = map
		return map


	def dirmap_save(self):
		fh = open(self.workingdir+"/dir.map", "w")
		fh.write(json.dumps(self.dirmap))
		fh.close()
		print "Directory map saved"


	def filemap_load(self):
		try:
			fh = open(self.workingdir+"/file.map")
			map = json.loads(fh.read())
			fh.close()
			print "File map loaded. %d entries." % len(map)
		except Exception, e:
			print "Error loading file map: ", e
			map = {}
		self.filemap = map
		return map


	def filemap_save(self):
		fh = open(self.workingdir+"/file.map", "w")
		fh.write(json.dumps(self.filemap))
		fh.close()
		print "File map saved"


	def file_in_filemap(self, filename):
		# Returns the FIDH for a file if it exists in the filemap.
		# If it doesn't, generates a new FIDH and returns that.
		hv = hash(filename)
		for key,value in self.filemap.iteritems():
			if value["hash"] == hv:
				return key
		fidh = hash(filename, True)
		return fidh

	def file_verify(self, filename, fidh):
		info = file_info(filename)
		if info["mtime"] > self.filemap[fidh]["mtime"]:
			print "File has been altered while kipstash was down. Sync needed."
			# TODO: Here we would normally just send a delta
			self.block_file_send(filename)
		else:
			self.filemap[fidh] = info


	def share_add(self, directory):
		if self.dirmap.has_key(directory):
			print "Share already exists in directory map."
		else:
			print "New (previously mapped) share."
			self.dirmap[directory] = {}

		for root, dirs, files in os.walk(directory):
			curname = root.split(directory)[1]
			if not self.dirmap[directory].has_key(curname):
				print "New directory %s found" % curname
				self.dirmap[directory][curname] = {}

			print "Walking %s..." % root
			for d in dirs:
				# print "DIR: %s" % d
				pass

			for f in files:
				filename = "%s/%s" % (root, f)
				if not self.dirmap[directory][curname].has_key(f):
					print "Found new file %s" % filename
					fidh = self.file_in_filemap(filename)
					self.dirmap[directory][curname][f] = fidh
					# New file found, better send the block.
					self.block_file_send(filename, fidh)
				else:
					self.file_verify(filename, fidh)
					

		self.dirmap_save()
		self.filemap_save()

			


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
		print "Client connected from %s:%d..." % fromaddr
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
		k = KipClient()
