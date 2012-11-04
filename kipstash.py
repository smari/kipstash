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
	try: fh = open(filename)
	except: return ""
	return hash_string(fh.read())


def hash_string(string, rand=False):
	h = hashlib.sha512()
	h.update(string)
	if rand:
		h.update("::" + "".join(["".join(random.sample("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4)) for x in range(500)]))
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
	# Write the config file to disk.
	config.write(open(filename, "w"))


def file_info(filename):
	# Build a full information dictionary about a file's current status.
	s = os.stat(filename)
	hv = hash(filename)
	return {"mode": s.st_mode, "size": s.st_size, "atime": s.st_atime, "mtime": s.st_mtime, "ctime": s.st_ctime, "hash": hv, "filename": filename}


def filemap_verify(filemap, dirmap, connection):
	# Verify the filemap. This might be deprecated (not actually sure!)
	if filemap == {}:
		return True
	pass


def diff(file):
	# Binary diff for delta creation
	# bsdiff.Diff("foo", "boo")
	pass


def patch(file):
	# Binary patch for delta application
	# bsdiff.Patch("foo", 3, [(3, 0, -1)], '\xfc\x00\x00', '')
	pass


class DirectoryMonitor:
	# Monitors a directory and its subdirectories
	# TODO: Does not currently monitor subdirectories
	
	def __init__(self, client):
		self.fam = _fam.open()
		self.mon = None
		self.client = client

	def start(self, dir):
		self.dir = dir
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
		filename = self.dir + "/" + event.filename
		if event.code2str() == "created":
			pass			

		if event.code2str() == "changed":
			print pprint.pformat(dir(event))
			print "Filename '%s' changed!" % filename
			fidh = self.client.filename_in_filemap(filename)
			print "FIDH: %s" % fidh
			print "Sending block to server..."
			self.client.block_file_send(filename, fidh)
			print "Sent."

			# self.connection.write("CHANGE EVENT ON %s\n" % event.filename)


class ClientConnection:
	# Manage a connection to a server.

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
		return self.ssl_sock.sendall(data)

	def read(self):
		return self.ssl_sock.recv()

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

		self.dirmon = DirectoryMonitor(self)
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
		if not os.path.exists(dir+"/client.pub"):
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


	def filename_in_filemap(self, filename):
		print "Searching for '%s' in filemap." % filename
		print "Filemap is currently:"
		print pprint.pformat(self.filemap)
		for key,value in self.filemap.iteritems():
			if value["filename"] == filename:
				return key
		return False

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
			self.block_file_send(filename, fidh)
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
					self.filemap[fidh] = file_info(filename)
					# New file found, better send the block.
					self.block_file_send(filename, fidh)
				else:
					print "Verifying previously added file."
					fidh = self.file_in_filemap(filename)
					self.file_verify(filename, fidh)
					

		self.dirmap_save()
		self.filemap_save()



class KipServer:
	def __init__(self):
		print "Server starting..."
		self.server_init()
		try:
			self.hostname = self.config.get("server", "hostname")
			self.port = self.config.getint("server", "port")
			self.server_certfile = self.config.get("server", "ssl_cert")
			self.server_keyfile = self.config.get("server", "ssl_key")
		except:
			print "Server hostname and port must be configured."
			sys.exit(0)

		self.socket_start()
		self.serve()
		print "Server exiting..."

	def socket_start(self):
		self.bindsocket = socket.socket()
		self.bindsocket.bind((self.hostname, self.port))
		self.bindsocket.listen(5)

		print "Server listening on %s:%d" % (self.hostname, self.port)

	def send_error(self, errorcode, errortext):
		# TODO: Determine whether it makes sense to encrypt messages to client
		print "ERROR %d: %s" % (errorcode, errortext)
		block = {"type": "error", "error": errorcode, "text": errortext}
		self.block_send(block)

	def block_send(self, block):
		# Sign every block before we send it.
		s = json.dumps(block)
		hv = hash_string(s)
		block["signature"] = self.priv.sign(hv)
		self.stream.send(block)

	def block_signature_verify(self, block, signature):
		s = json.dumps(block)
		hv = hash_string(s)
		for key in self.clientkeys:
			if key.verify(hv, (signature,)):
				return key
		return None

	def block_parse(self, block):
		try:
			assert(type(block)==dict)		# All blocks must be dicts
			assert(block.has_key("type"))		# All blocks must report their type
		except AssertionError, e:
			self.send_error(101, "Invalid block format")
		try:
			assert(block.has_key("signature"))	# All blocks must be signed
		except AssertionError, e:
			self.send_error(102, "All blocks must be signed")

		signature = block.pop("signature")
		clientkey = self.block_signature_verify(block, signature)
		if clientkey == None:
			self.send_error(200, "Unknown user key or bad signature. GOODBYE!")
			self.stream.shutdown(socket.SHUT_RDWR)
			self.stream.close()
			return

		block["client"] = clientkey

		# At this point, we've verified the validity of the block and the identity of the client.
		if	type == "file":		self.block_parse_file(block)
		elif 	type == "delta":	self.block_parse_delta(block)
		elif	type == "query":	self.block_parse_query(block)
		elif	type == "delete":	self.block_parse_delete(block)
		elif	type == "share":	self.block_parse_share(block)
		elif	type == "error":	self.block_parse_error(block)
		else:	self.send_error(103, "Block type unknown")
	
	def block_parse_file(self, block):
		try:	assert(block.has_key("fidh"))		# All file blocks must have a fidh
		except AssertionError, e:
			self.send_error(120, "File block missing FIDH")

		try:	assert(block.has_key("to"))		# All file blocks must have a TO
		except AssertionError, e:
			self.send_error(121, "File block missing TO")
		
		# TODO:
		# If (FIDH, clientkey hash) pair exist in storage, remove existing file and deltas
		# Push (FIDH, clientkey hash, file) to storage somewhere


	def block_parse_delete(self, block):
		try:	assert(block.has_key("fidh"))		# All delete blocks must have a fidh
		except AssertionError, e:
			self.send_error(120, "Delete block missing FIDH")

		# TODO:
		# If (FIDH, clientkey hash) pair exist in storage, remove existing file and deltas


	def block_parse_delta(self, block):
		try:	assert(block.has_key("fidh"))		# All file blocks must have a fidh
		except AssertionError, e:
			self.send_error(120, "Delta block missing FIDH")

		try:	assert(block.has_key("to"))		# All file blocks must have a TO
		except AssertionError, e:
			self.send_error(121, "File block missing TO")

		# TODO:
		# Push (FIDH, clientkey hash, delta) to storage somewhere

	def block_parse_query(self, block):
		pass

	def block_parse_error(self, block):
		pass

	def block_parse_share(self, block):
		pass

	def client_manage(self):
		decoder = json.JSONDecoder()
		data = True	# Start as True to pass into the loop.
		# null data means the client is finished with us
		buffer = ""
		while data:
			data = self.stream.recv()
			buffer += data

			if buffer[0] != '{':
				self.send_error(self.stream, 100, "Invalid block format")
				buffer = ""
				continue
			try:
				blob, mark = decoder.raw_decode(buffer)
				buffer = buffer[mark:]
				self.block_parse(blob)
			except ValueError:
				# Not a valid JSON blob yet.
				continue

	def serve(self):
		# TODO: fork() or thread to allow multiple simultaneous connections
		while True:
			newsocket, fromaddr = bindsocket.accept()
			print "Client connected from %s..." % fromaddr
			connstream = ssl.wrap_socket(newsocket, server_side=True, 
					certfile=self.server_certfile, keyfile=self.server_keyfile,
					ssl_version=ssl.PROTOCOL_TLSv1)
			print "SSL handshake complete."
			try:
				self.stream = connstream
				self.client_manage(connstream)
			finally:
				connstream.shutdown(socket.SHUT_RDWR)
				connstream.close()
	

	def server_init(self, dir="~/.kipstash"):
		# Initialize the server.
		# TODO: Make sure the server can recover cleanly from missing or corrupt files
		# TODO: Make location of server keys configurable
		dir = os.path.expanduser(dir)
	
		if not os.path.exists(dir):
			print "Initializing server for the first time ever."
			os.mkdir(dir, 0700)

		self.config = config_load(dir+"/kipstash.cfg")

		if not os.path.exists(dir+"/server.pub"):
			print "Generating server keys..."
			server_pubkey = open(dir+"/server.pub", "w")
			server_privkey = open(dir+"/server.sec", "w")
			priv, pub = keys_generate()
			server_pubkey.write(pub)
			server_privkey.write(priv)
			server_pubkey.close()
			server_privkey.close()
			self.priv = get_privkey(priv)
			self.pub = get_pubkey(pub)
		else:
			# TODO: Make this fail less hard.
			self.priv = get_privkey(open(dir+"/server.sec").read())
			self.pub = get_pubkey(open(dir+"/server.pub").read())
			print "Server keys loaded..."

		self.clientkeys = []
		clientkeysfile = dir+"/clientkeys.json"	# TODO: Make this configurable
		try:
			ke = open(clientkeysfile).read()
			keys = json.loads(ke)
			for key in keys:
				self.clientkeys.append(get_pubkey(key))
		except IOError, e:
			print "Error loading client keys from %s: %s." % (clientkeysfile, e)
		except ValueError, e:
			print "Error loading client keys from %s: %s." % (clientkeysfile, e)

		if self.clientkeys == []:
			print "No reason to run without any client keys. Bailing."
			sys.exit(0)


if __name__ == "__main__":
	servermode = False

	optlist, args = getopt.getopt(sys.argv[1:], 's')
	for arg, value in optlist:
		if arg == "-s":
			servermode = True

	if servermode:
		k = KipServer()
	else:
		k = KipClient()
