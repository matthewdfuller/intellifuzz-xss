<?php

include('php-functions.php');

?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

<title>XSS Test Suite | Attributes</title>

</head>
<body>
    <h1>XSS Test Suite | Attributes</h1>
    <p>Sometimes, user provided data is used as an attribute of an html element. This can be done inside of empty tags such as &lt;br /&gt; or &lt;input /&gt;
    or inside or closed tags such as &lt;div&gt;&lt;/div&gt; or &lt;span&gt;&lt;/span&gt;. An attribute's value appears in quotes such as in this example:
    &lt;div id=&quot;value&quot;&gt;&lt;/div&gt;. Here, the attribute is "id" and the attribute's value is "value."</p>
    
    <p>Use the parameters "a" - "d" (one, many, or all at once) to provide input. View the source to see what is happening.</p>
    
    <div id="main">
    In this example, the provided, unescaped value is part of the closed tag "div." A successful xss usually means closing this tag and executing a script.<br/>
    Use parameter "a".
    <div id="a" attr="<?php echo $_GET['a']; ?>">
    </div><br/>

    In this example, the provided, unescaped value is part of the empty tag "br." A successful xss usually means closing the empty tag to execute a script.<br/>
    Use parameter "b".
    <br attr="<?php echo $_GET['b']; ?>" /><br/>
    
    Here, we have an input empty tag that also filters out script tags. See if you can get it to execute.<br/>
    Use parameter "c".
    <input type="textbox" value="<?php echo remove_script($_GET['c']); ?>" /><br/><br/>
    
    Finally, here is a div using htmlentities to properly filter the input.<br/>
    Use parameter "d".
    <div id="d" attr="<?php echo htmlentities($_GET['d']); ?>">
    </div><br/>
    
    </div>
    <h2>Source Code</h2>
    <textarea id="srccode" style="width: 90%; height: 500px;"></textarea>
    <script>
        document.getElementById('srccode').value = document.getElementById('main').innerHTML
    </script>
 
</body>
</html>
