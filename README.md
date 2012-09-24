====================
Intellifuzz
====================

========
Overview
========
Intellifuzz is a Python script designed to not only determine if a cross-site scripting attack is possible, but also determine the exact payload needed.
Many web scanners and fuzzers operate by using a long list of possible payloads and recording the response to see if the payload is reflected. However,
just because a payload is reflected does not mean it will execute. For example, if the payload is reflected as an HTML attribute, a carefully crafted
string must be created to first break out of the attribute using quotes, then potenitally break out of the tag, then finally launch the script.
Intellifuzz aims to take care of crafting the payload for you by first detecting the location of the parameter reflection, then using a number of tests
to determine what characters are needed to cause a successful execution.

========
Usage
========
At the moment, Intellifuzz only works with GET parameters. POST support is coming soon. To use Intellifuzz, replace the parameter you wish to test with the
keyword "XSSHEREXSS" (all caps). Paste the full URL, in quotes, as the first parameter on the command line, like so:

$python intellifuzz "http://site.com/page.php?param=XSSHEREXSS"


========
What Can Intellifuzz Find?
========
Intellifuzz is currently designed to locate potential XSS attack vectors in:
*HTML Comments such as <!-- comment with reflection here -->
*Empty tag attributes such as <br attr="param"/>
*Full tag attributes such as <div attr="param></div>
*Data/Plaintext on a page such as <div>param</div>
*Script usage such as <script>var test = param</script>

========
Limitations
========
Intellifuzz is in an early beta stage and has several limitations:
*Only one parameter can be scanned at once (i.e. "http://site.com/page.php?param1=XSSHEREXSS&param2=XSSHEREXSS" would not work)
*Reflections in 404 Error pages are not scanned
*Limited support for parameter reflection inside <script> tags
*XSS in HTML tag attributes without double quotes are not supported (i.e. <div attr=param></div> or <div attr='param'></div>)
*POST data is not yet supported
*Potential false positives