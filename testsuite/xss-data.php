<?php

include('php-functions.php');

?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

<title>XSS Test Suite | Data</title>

</head>
<body>
    <h1>XSS Test Suite | Data</h1>
    <p>Some of the most common examples of XSS are when input parameters are used directly as data on the page. They can be reflected
    inside of div tags, paragraph tags, spans, etc. The most basic of XSS payloads will work in these cases, unless the input is being
    escaped. Even then, if the escaping is not done properly, the XSS can still be executed.</p>
    
    <p>Use the parameters "a" - "e" (one, many, or all at once) to provide input. View the source to see what is happening.</p>
    
    <div id="main">
        This page echoes out the parameter "a" as plaintext here: <?php echo $_GET['a']; ?><br/><br/>
        
        Now, the parameter "b" is echoed here, but the semi-colons are removed: <?php echo remove_semi_colon($_GET['b']); ?><br/><br/>
        
        Next, the script tags are removed for parameter "c": <?php echo remove_script($_GET['c']); ?><br/><br/>
        
        The PHP function, addslashes is used for parameter "d": <?php echo addslashes($_GET['d']); ?><br/><br/>
        
        And finally, htmlentities is used on parameter "e": <?php echo htmlentities($_GET['e']); ?>
    
    </div>
    
    <h2>Source Code</h2>
    <textarea id="srccode" style="width: 90%; height: 500px;"></textarea>
    <script>
        document.getElementById('srccode').value = document.getElementById('main').innerHTML
    </script>
</body>
</html>