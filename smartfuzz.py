#!/usr/bin/env python

"""
  Python XSS Fuzzer
  A python based fuzzer that attempts to determine whether XSS can exist given a parameter to fuzz
  It determines which characters are available for use in a payload and intelligently generates a
  payload that will properly escape the html if possible.
  Copyright: Matthew Fuller, http://matthewdfuller.com
  Usage: python fuzz.py http://site.com/full-path-with-params?param=XSSHEREXSS
""" 
from urlparse import urlparse, parse_qs
from HTMLParser import HTMLParser
import urllib2
import sys
import re

#GLOBAL VARIABLES
XSSCHECKVAL = "XSSHEREXSS"      #Must be plaintext word unlikely to appear on the page
CHARS_TO_CHECK = ['"', '\'', '>', '<', ':', ';', '/', '\\', ']', '}']
ALLOWED_CHARS = []
URL = ""
NUM_REFLECTIONS = 0             #Number of times the parameter value is displayed in the code.

IN_DOUBLE_QUOTES = False
IN_SINGLE_QUOTES = False
IN_TAG_ATTRIBUTE = False        #Ex: <tag attr="XSSHERE"></tag>
IN_TAG_NON_ATTRIBUTE = False    #Ex: <tag>XSSHERE</tag>
IN_SCRIPT_TAG = False

CURRENTLY_OPEN_TAGS = []        #Currently open is modified as the html is parsed
OPEN_TAGS = []                  #Open is saved once xsscheckval is found
TAGS_TO_IGNORE = ['html','body','br']             #These tags are normally empty <br/> or should be ignored because don't need to close them but sometimes, not coded properly <br> and missed by the parser.
TAG_WHITELIST = ['input', 'textarea']             #Tags to break out of specifically

def main():
    #COMMAND LINE PARSING ARGUMENTS
    if (len(sys.argv) != 2 or XSSCHECKVAL not in sys.argv[1]):
        exit("Usage: python smartfuzz.py <FULL URL REPLACING PARAM TO FUZZ WITH " + XSSCHECKVAL + ">\nExample: python smartfuzz.py http://site.com/?param=" + XSSCHECKVAL + "\n")
    global URL
    URL = sys.argv[1]

    print "\nProvided URL: " + URL
    
    #LOAD THE PROVIDED PAGE TO SEE IF VALID URL, CATCH ALL NON-SUCCESS RESPONSE CODES
    print "\n[Can URL be loaded?]"
    init_resp = make_request(URL)   #Function will exit with error if fails.
    print bcolors.OKGREEN + "SUCCESS." + bcolors.ENDC
    
    #IF VALID URL, CHECK FOR REFLECTED CHECK VAL IN RESPONSE
    print "\n[Does response contain the parameter value?]"
    if(XSSCHECKVAL in init_resp):
        #PRINT NUM LINES CONTAINING RESPONSE
        global NUM_REFLECTIONS
        NUM_REFLECTIONS = init_resp.count(XSSCHECKVAL)
        print bcolors.OKGREEN + "SUCCESS." + bcolors.ENDC + " Reflected in code " + str(NUM_REFLECTIONS) + " time(s)."
        
    else:
        exit(bcolors.FAIL + "ERROR." + bcolors.ENDC + " Check value not in response. Nothing to test. Exiting...\n")
    
    #Loop through and run tests for each occurance
    for i in range(NUM_REFLECTIONS):
        print "\n\nTESTING OCCURANCE NUMBER: " + str(i + 1)
        scan_occurance(init_resp, (i+1))
        #Reset globals for next instance
        global ALLOWED_CHARS, IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG, CURRENTLY_OPEN_TAGS, OPEN_TAGS
        ALLOWED_CHARS, CURRENTLT_OPEN_TAGS, OPEN_TAGS = [], [], []
        IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG = False, False, False, False, False
    

#FUNCTIONS!
#scan_occurance() runs scan for a reflected instance (a param can be used multiple times on a page)
def scan_occurance(init_resp, occurance_num):
    #CHECK FOR ALLOWED CHARACTERS
    character_check()
    
    #NOW DETERMINE IF PLAINTEXT OR INSIDE A TAG
    #Basically, want to first determine if we are inside a tag or in plaintext. If in plaintext, jump to attacks.
    #If in tag, find if in quotes. If so, break out. If not, read left until out of tag. Must account for <a open tags
    #as well as <textarea> closed tags. Read right. If find </ or /> then inside.
    
    #READ RIGHT AND LEFT TO DETERMINE MORE INFO ABOUT LOCATION AND SURROUNDING TAGS AND SYMBOLS
    XSSCHECKVAL_search = re.search(XSSCHECKVAL, init_resp)
    XSSCHECKVAL_pos = XSSCHECKVAL_search.start()
    #print "Found at position: " + str(XSSCHECKVAL_pos)
    everything_after = init_resp[XSSCHECKVAL_pos:]
    #print everything_after
    
    #Move to left and right of XSSCHECKVAL to see if in quotes using substrings
    print "\n[Is xss check in single or double quotes?]"
    if(init_resp[XSSCHECKVAL_pos - 1:XSSCHECKVAL_pos] == "\"" and init_resp[XSSCHECKVAL_pos + (len(XSSCHECKVAL)):XSSCHECKVAL_pos + (len(XSSCHECKVAL) + 1)] == "\""):
        global IN_DOUBLE_QUOTES
        IN_DOUBLE_QUOTES = True
        print "In double quotes."
    elif(init_resp[XSSCHECKVAL_pos - 1:XSSCHECKVAL_pos] == "'" and init_resp[XSSCHECKVAL_pos + (len(XSSCHECKVAL)):XSSCHECKVAL_pos + (len(XSSCHECKVAL) + 1)] == "'"):
        global IN_SINGLE_QUOTES
        IN_SINGLE_QUOTES = True
        print "In single quotes."
    else:
        print "Not in single or double quotes."

    #Begin parsing HTML tags to see where located
    print "\n[Checking for location of xsscheckval.]"
    parser = MyHTMLParser()
    try:
        parser.feed(init_resp)
    except Exception as e:
        if(e == "comment"):
            print "Inside a comment."
        elif(e == "script"):
            print "Inside a script tag."
        elif(e == "attribute"):
            print "Inside a tag attribute." #+ last opened tag
        print e
    except:
        print bcolors.FAIL + "ERROR." + bcolors.ENDC + " That was bad. Some sort of parsing error happened. Try rerunning?"


#make_request() makes a URL request given a provided URL and returns the response
def make_request(in_url):
    try:
        req = urllib2.Request(in_url)
        resp = urllib2.urlopen(req)
        return resp.read()
    except:
        exit("\n" + bcolors.FAIL + "ERROR" + bcolors.ENDC + " Could not open URL. Exiting...\n")

#character_check() loops through and tests each character to see if it is being escaped
#if a character is not escaped, it is added to the ALLOWED_CHARS array which is printed at the end
def character_check():
    print "\n[Which chacters are allowed?]"
    for char_to_check in CHARS_TO_CHECK:
        #print "Testing char: " + char_to_check
        check_string = "XSS" + char_to_check + "XSS"
        check_url = URL.replace(XSSCHECKVAL, check_string)
        check_response = make_request(check_url)
        if(check_string in check_response):
            #print bcolors.OKGREEN + "SUCCESS. " + bcolors.ENDC + "Adding " + char_to_check + " to allowed chars list."
            global ALLOWED_CHARS
            ALLOWED_CHARS.append(char_to_check)
        else:
            #print bcolors.FAIL + "ERROR. "  + bcolors.ENDC + "Char: " + char_to_check + " was escaped as: "
            for line in check_response.splitlines():
                if ("XSS" in line):
                    print line
    ALLOWED_CHARS_str = ""
    for char in ALLOWED_CHARS:
        ALLOWED_CHARS_str += char + " "
    print "Allowed characters: " + ALLOWED_CHARS_str

#HTML Parser class
class MyHTMLParser(HTMLParser):
    global CURRENTLY_OPEN_TAGS
    global OPEN_TAGS
    
    def handle_comment(self, data):
        if(XSSCHECKVAL in data):
            raise Exception("comment")
    
    def handle_startendtag(self, tag, attrs):
        if (XSSCHECKVAL in str(attrs)):
            raise Exception("Found XSSCHECKVAL")
            
    def handle_starttag(self, tag, attrs):
        #print CURRENTLY_OPEN_TAGS
        if(tag not in TAGS_TO_IGNORE):
            CURRENTLY_OPEN_TAGS.append(tag)
        if (XSSCHECKVAL in str(attrs)):
            if(tag == "script"):
                raise Exception("script")
            else:
                raise Exception("attribute")
            raise Exception("Found XSSCHECKVAL")
            
    def handle_endtag(self, tag):
        if(tag not in TAGS_TO_IGNORE):
            CURRENTLY_OPEN_TAGS.remove(tag)
            
    def handle_data(self, data):
        if (XSSCHECKVAL in data):
            raise Exception("data")

#SET COLORS
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

#RUN MAIN FUNCTION
if __name__ == "__main__":
    main()