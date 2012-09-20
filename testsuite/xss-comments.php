<?php

include('php-functions.php');

?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

<title>XSS Test Suite | Comments</title>

</head>
<body>
    <h1>XSS Test Suite | Comments</h1>
    <p>Sometimes, user provided data is used within an HTML comment. For example, a dynamically generated page may use a parameter such as
    language=en-us to create a comment that says "the page language is: en-us".</p>
    
    <p>Use the parameters "a" - "f" (one, many, or all at once) to provide input. View the source to see what is happening.</p>
    
    <div id="main">
    <!--This is an html comment that doesn't escape user input (use param a): <?php echo $_GET['a']; ?> -->
    
    <!--This comment removes only semi-colons (use param b): <?php echo remove_semi_colon($_GET['b']); ?> -->
    
    <!--This comment removes script tags (use param c): <?php echo remove_script($_GET['c']); ?> -->
    
    <!--This comment is escaped using PHP's addslashes (use param d): <?php echo addslashes($_GET['d']); ?> or something -->
    
    <!--This comment is escaped using PHP's htmlentities (use param e): <?php echo htmlentities($_GET['e']); ?> or something -->
    
    <!--This comment is escaped using PHP's htmlspecialchars (use param f): <?php echo htmlspecialchars($_GET['f']); ?> or something -->
    </div>
    
    <h2>Source Code</h2>
    <textarea id="srccode" style="width: 90%; height: 500px;"></textarea>
    <script>
        document.getElementById('srccode').value = document.getElementById('main').innerHTML
    </script>
</body>
</html>
