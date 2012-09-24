#Intellifuzz

##Overview
Intellifuzz is a Python script designed to not only determine if a cross-site scripting attack is possible, but also determine the exact payload needed
to *cleanly* break out of the code.
Many web scanners and fuzzers operate by using a long list of possible payloads and recording the response to see if the payload is reflected. However,
just because a payload is reflected does not mean it will execute. For example, if the payload is reflected as an HTML attribute, a carefully crafted
string must be created to first break out of the attribute using quotes, then potenitally break out of the tag, then finally launch the script.
Intellifuzz aims to take care of crafting the payload for you by first detecting the location of the parameter reflection, then using a number of tests
to determine what characters are needed to cause a successful execution.

##Usage
At the moment, Intellifuzz only works with GET parameters. POST support is coming soon. To use Intellifuzz, replace the parameter you wish to test with the
keyword "XSSHEREXSS" (all caps). Paste the full URL, in quotes, as the first parameter on the command line, like so:

```
$python intellifuzz.py "http://site.com/page.php?param=XSSHEREXSS"
```

##Testing
In the /testsuite folder there are a number of PHP pages that can be used to test the scanner against various attack locations. You may download
and run them on any PHP server. A live copy is also hosted, for the time being, at: http://blasze.com/xsstestsuite/

##What Can Intellifuzz Find?
Intellifuzz is currently designed to locate potential XSS attack vectors in:
* HTML Comments such as ```<!-- comment with reflection here -->```
* Empty tag attributes such as ```<br attr="param"/>```
* Full tag attributes such as ```<div attr="param></div>```
* Data/Plaintext on a page such as ```<div>param</div>```
* Script usage such as ```<script>var test = param</script>```

##Limitations
Intellifuzz is in an early beta stage and has several limitations:
* Only one parameter can be scanned at once (i.e. "http://site.com/page.php?param1=XSSHEREXSS&param2=XSSHEREXSS" would not work)
* Reflections in 404 Error pages are not scanned
* Limited support for parameter reflection inside ```<script>``` tags
* XSS in HTML tag attributes without double quotes are not supported (i.e. ```<div attr=param></div>``` or ```<div attr='param'></div>```)
* POST data is not yet supported
* Potential false positives

##Future Features
* Detect single or double quote attribute usage and dynamically alter payload to match
* Better script tag support
* Improve false positive rate
* Support HTML error pages (404s, etc.)
* POST data usage
* Chrome-specific payloads that bypass Chrome's XSS filter
* Improved CLI error messages that explain exactly why an attack worked or failed

##Technical Details
The script works by first reading in the URL. If the keyword, XSSHEREXSS is found for one parameter, it continues. It then tests the URL to see if it can be
successfully loaded. If so, the response code is checked to see if the keyword is present. Without the keyword, a reflected XSS attack is impossible. If the
keyword is found, the script determines the number of times the keyword appears (different attack vectors will be present for each reflection location). For
each reflection, the response is passed to an HTML parser which determines where in the HTML code the reflection is found. There are several configured
locations: an HTML comment, an empty tag attribute, a tag attribute, HTML data or plaintext, or within a script. Each location has its own function which is
called to attempt to generate the correct payload to match the location.

The "break" functions are responsible for determining if an ideal payload will work. If the ideal payload fails, new tests are run to determine why. For example,
some sites block script tags, but not image tags, so a payload involving image onerror attributes is generated. If the dynamically generated payloads fail, the
function resorts to fuzzing from a lists of paylaods known to work in that specific location. For example, if the parameter is reflected in an HTML comment,
the code ```-->``` is appended to the beginning of each payload to ensure the comment is broken out of first.

Every payload attempt is also tested for "cleanliness." This means that, if the ideal payload works, the viewable aspect of the page seen by the victim would not
be affected. With some XSS attacks, the escaping needed causes the rest of the page code to become part of the text shown to the visitor. By using a clean attack,
the correct code is appended to the end of an attack to allow the page to function generally as it should. For example, if the code was originally:
```<div attr="param"></div>``` then the paylaod generated would be: ```"<script>alert(1);</script><div attr="``` The "div attr=" at the end allows a new div to be
created in the code, thus preventing HTML syntax errors.

If a clean attack will not work, a warning is given that invalid HTML is being used.

At the conclusion of the script, a full list of possible payloads is provided. After each occurance, a URL-encoded string is provided as well for easy copy/pasting
into the browser.