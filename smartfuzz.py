#!/usr/bin/env python

"""
  Python XSS Fuzzer
  A python based fuzzer that attempts to determine whether XSS can exist given a parameter to fuzz
  It determines which characters are available for use in a payload and intelligently generates a
  payload that will properly escape the html if possible, using the fewest http requests as possible.
  Copyright: Matthew Fuller, http://matthewdfuller.com
  Usage: python smartfuzz.py http://site.com/full-path-with-params?param=XSSHEREXSS
""" 
from urlparse import urlparse, parse_qs
from HTMLParser import HTMLParser
import urllib2
import sys
import re

#######################################################################################################################
#GLOBAL VARIABLES
#######################################################################################################################
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
TAGS_TO_IGNORE = ['html','body','br','div']             #These tags are normally empty <br/> or should be ignored because don't need to close them but sometimes, not coded properly <br> and missed by the parser.
TAG_WHITELIST = ['input', 'textarea']             #Tags to break out of specifically

OCCURENCE_NUM = 0
OCCURENCE_PARSED = 0

#######################################################################################################################
# MAIN FUNCTION
#######################################################################################################################
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
    
    #Loop through and run tests for each occurence
    for i in range(NUM_REFLECTIONS):
        print "\n\nTESTING OCCURENCE NUMBER: " + str(i + 1)
        global OCCURENCE_NUM
        OCCURENCE_NUM = i+1
        scan_occurence(init_resp)
        #Reset globals for next instance
        global ALLOWED_CHARS, IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG, CURRENTLY_OPEN_TAGS, OPEN_TAGS, OCCURENCE_PARSED
        ALLOWED_CHARS, CURRENTLY_OPEN_TAGS, OPEN_TAGS = [], [], []
        IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG = False, False, False, False, False
        OCCURENCE_PARSED = 0
    
#######################################################################################################################
# OTHER FUNCTIONS
#######################################################################################################################
#make_request() makes a URL request given a provided URL and returns the response
def make_request(in_url):
    try:
        req = urllib2.Request(in_url)
        resp = urllib2.urlopen(req)
        return resp.read()
    except:
        exit("\n" + bcolors.FAIL + "ERROR" + bcolors.ENDC + " Could not open URL. Exiting...\n")

#scan_occurence() runs scan for a reflected instance (a param can be used multiple times on a page)
def scan_occurence(init_resp):
    #Check for allowed characters
    character_check()

    #Begin parsing HTML tags to see where located
    html_parse(init_resp)

#character_check() loops through and tests each character to see if it is being escaped
#if a character is not escaped, it is added to the ALLOWED_CHARS array which is printed at the end
def character_check():
    print "\n[Which chacters are allowed?]"
    global ALLOWED_CHARS
    for char_to_check in CHARS_TO_CHECK:
        check_string = "XSSSTART" + char_to_check + "XSSEND"
        check_url = URL.replace(XSSCHECKVAL, check_string)
        check_response = make_request(check_url)
        
        #Loop to get to right occurence
        occurence_counter = 0
        for m in re.finditer('XSSSTART', check_response):
            #print( 'found', m.start(), m.end() )
            occurence_counter += 1
            if((occurence_counter == OCCURENCE_NUM) and (check_response[m.start():m.start()+15] == check_string)):
                ALLOWED_CHARS.append(char_to_check)
                break

    ALLOWED_CHARS_str = ""
    for char in ALLOWED_CHARS:
        ALLOWED_CHARS_str += char + " "
    print "Allowed characters: " + ALLOWED_CHARS_str

#html_parse() locates the xsscheckval and determins where it is in the HTML
def html_parse(init_resp):
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
        print str(e) + " tags: " +  str(CURRENTLY_OPEN_TAGS)
    except:
        print bcolors.FAIL + "ERROR." + bcolors.ENDC + " That was bad. Some sort of parsing error happened. Try rerunning?"
        
#BREAK OUT FUNCTIONS - used to break out of code and determine xss
def break_script():
    print ""

#######################################################################################################################
# CLASSES
#######################################################################################################################

#HTML Parser class
class MyHTMLParser(HTMLParser):
    def handle_comment(self, data):
        global OCCURENCE_PARSED
        if(XSSCHECKVAL in data):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
                raise Exception("comment")
    
    def handle_startendtag(self, tag, attrs):
        global OCCURENCE_PARSED
        global OCCURENCE_NUM
        if (XSSCHECKVAL in str(attrs)):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
                raise Exception("startend tag attribute")
            
    def handle_starttag(self, tag, attrs):
        global CURRENTLY_OPEN_TAGS
        global OPEN_TAGS
        global OCCURENCE_PARSED
        #print CURRENTLY_OPEN_TAGS
        if(tag not in TAGS_TO_IGNORE):
            CURRENTLY_OPEN_TAGS.append(tag)
        if (XSSCHECKVAL in str(attrs)):
            if(tag == "script"):
                OCCURENCE_PARSED += 1
                if(OCCURENCE_PARSED == OCCURENCE_NUM):
                    raise Exception("script")
            else:
                OCCURENCE_PARSED += 1
                if(OCCURENCE_PARSED == OCCURENCE_NUM):
                    raise Exception("attribute")

    def handle_endtag(self, tag):
        global CURRENTLY_OPEN_TAGS
        global OPEN_TAGS
        global OCCURENCE_PARSED
        if(tag not in TAGS_TO_IGNORE):
            CURRENTLY_OPEN_TAGS.remove(tag)
            
    def handle_data(self, data):
        global OCCURENCE_PARSED
        if (XSSCHECKVAL in data):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
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