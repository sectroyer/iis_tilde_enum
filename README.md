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
usage: tilde_enum.py [-h] [-d PATH_WORDLISTS] [-e PATH_EXTS] [-f]
                     [-o OUT_FILE] [-p PROXY] [-u URL] [-v VERBOSE_LEVEL]
                     [-w WAIT] [--resume RESUME_STRING]
                     [--limit-ext LIMIT_EXTENSION]

Exploits and expands the file names found from the tilde enumeration vuln

optional arguments:
  -h, --help            show this help message and exit
  -d PATH_WORDLISTS     Path of wordlists file
  -e PATH_EXTS          Path of extensions file
  -f                    Force testing even if the server seems not vulnerable
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
$  ./tilde_enum.py -u "http://iis/subdir" -w 0.1 -o output/enum_result.txt
[-]  Testing with dummy file request http://iis/subdir/egSHcspvs8bQ5.htm
[-]    URLNotThere -> HTTP Code: 404, Response Length: 1379
[-]  Testing with user-submitted http://iis/subdir/
[-]    URLUser -> HTTP Code: 403, Response Length: 218
[!]  WARNING: We did not receive an HTTP response code 200 back with given url.
[-]  User-supplied delay detected. Waiting 0.1 seconds between HTTP requests.
[+]  The server is reporting that it is IIS (Microsoft-IIS/6.0).
[+]  The server is vulnerable to the IIS tilde enumeration vulnerability..
[+]  Found file:  descri~1.htm
[+]  Found file:  index-~1.htm
[+]  Found file:  index-~2.htm
[-]  Finished doing the 8.3 enumeration for /subdir/.

---------- OUTPUT START ------------------------------
[+] Raw results:
http://iis/subdir/descri~1.htm
http://iis/subdir/index-~1.htm
http://iis/subdir/index-~2.htm

[+] Existing files found:
http://iis/subdir/description.html

[+] Existing Directories found: None.
---------- OUTPUT COMPLETE ---------------------------
</pre>
