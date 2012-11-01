kip stash - a kind of open source secure dropbox / wuala replacement
====================================================================

Authors: 
========

Smari McCarthy
Florian Walther
Pablo

Background:
===========

Many not so computer savvy human rights activists around the world use dropbox 
to backup and share as well as work collaborative on files. There are several threats associated with dropbox like the fact that files are stored in dropbox 
are not encrypted by default so it can be retrieved in cleartext by third parties. Also the whole infrastructure is in the hand of one private corporation 
with can be set under pressure. Files are not secure agains manipulation (while 
stored on the server) and many more.

Therefore this projects tries to come up with a secure by default, robust and 
easy to use solution for activists.

Git Repository
==============

The git repository is at: ssh://git@projects.grauenhagen.de:/kipstash.git, the 
repository is not public. If you want to help develop this software talk to 
scusi@snurn.de

Files:
======

kipstash.py             	Client and Server, can act as both
~/.kipstash/kipstash.cfg    INI-format config file containing [client] and 
							[server] sections (depending on which you're 
							intending to run
								
~/.kipstash/client.pub 		Base64 encoded JSON format RSA public key generated 
							for client (only if kipstash has been run in client 
							mode)
							
~/.kipstash/client.sec      Base64 encoded JSON format RSA private key generated 
							for client   (only if kipstash has been run in 
							client mode)
							
~/.kipstash/server.pub      Base64 encoded JSON format RSA public key generated 
							for server  (only if kipstash has been run in server 
							mode)
							
~/.kipstash/server.sec      Base64 encoded JSON format RSA private key generated 
							for server  (only if kipstash has been run in server 
							mode)

~/.kipstash/cert.pem  		For server operation, here is an SSL certificate, 
							stored somewhere, referred to by kipstash.cfg

~/.kipstash/key.pem         For server operation, here is an SSL private key, 
							stored somewhere, referred to by kipstash.cfg

Sample config file
==================

[client]
share_dir = /home/smari/Public
server = 127.0.0.1

[server]
hostname = 0.0.0.0
port = 3477
ssl_cert = /home/smari/.kipstash/cert.pem
ssl_key = /home/smari/.kipstash/key.pem

Protocol
========

Blocks are transferred. Blocks have different types, including: File, Delta, Structure, Login and Query.

Block format
============

[BEGIN RSA SIGNED BLOCK
    [BEGIN HEADER
    END HEADER]
        [BEGIN PAYLOAD
            [BEGIN RSA ENCRYPTED BLOCK
                PAYLOAD JSON FORMAT
            END RSA ENCRYPTED BLOCK]
        END PAYLOAD]
END RSA SIGNED BLOCK ]

Filemap format
==============

On the client side, a file map is maintained which understands the status of all the files currently stored

Each file, when it is first detected, is given a 512 bit unique ID number which will follow it forever, regardless of renames or changes to the file.
This ID is determined by the SHA512 of the file at that point in time, for now.

When a new file is detected, first we check if it is 

dirmap = {

        "SHARE1":       {
                                "files":        {
                                        "filename":     "file ID hash",
                                },
                                "directories":  {
                                        "dirname":      {
                                                "files":        ...
                                        },
                                        "dirname2":     {

                                        }
                                },
                        },

        "SHARE2":       {
                                "files":        {
                                },
                                "directories":  {

                                },
                        },

        }


filemap = {
       "file ID hash": {
                                "mtime":        ...,
                                "mode":         ...,
                                "size":         ...,
                                "atime":
                                "ctime":
                                "hash":
                                "filename:
                        }
}



Transmitted block:
==================

(SIGNATURE
{"file ID hash": ...,
        "blob": ...,    [crypted blob]
        "type": ...,    [file, delta, ...]
}
)

 -- > Server

{"file ID hash": ...,
        "blob": ...,    [crypted blob]
        "signature":    ...,
        "user":         ...,
}

QUERY:
{"type":        "query"
 "FIH":  ...
 "not": [... diffs ...]}

RESPONSE:
        Any Diff or File objects that have applied to FIH, which aren't in the
        "not" list, and are from users which I have authorized to edit the file
        with me.