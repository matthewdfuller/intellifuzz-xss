<?php

include('php-functions.php');

?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

<title>XSS Test Suite | Script</title>

</head>
<body>
    <h1>XSS Test Suite | Script</h1>
    <p>In many cases, a parameter provided by the user is used directly within JavaScript on the page. This allows for potential XSS
    attacks if the parameter is not escaped first. The attack payloads when scripts are used are a bit different since the script tags
    do not need to be part of the payload itself. This is because the echoed parameter is already inside a script. Try these!</p>
    
    <p>Use the parameters "a" - "f" (one, many, or all at once) to provide input. View the source to see what is happening.</p>
    
    <div id="main">
        Here is a script where the parameter "a" is assigned to a value in the script. No escaping is done.
        <script type="text/javascript">
            var temp_val = <?php echo $_GET['a']; ?>;
        </script><br/><br/>
        
        Here is another example where the parameter "b" is used as part of a string.
        <script type="text/javascript">
            document.getElementById('not_real').innerHTML = "A long string with user input <?php echo $_GET['b']; ?>"
        </script><br/><br/>
        
        JavaScript may use the provided value in a JSON string.
        <script type="text/javascript">
            var myJSONObject = {"value1": [{"name": "bob", "method": "post", "value-c": "<?php echo $_GET['c']; ?>"}]};
        </script><br/><br/>
    </div>
    
    <h2>Source Code</h2>
    <textarea id="srccode" style="width: 90%; height: 500px;"></textarea>
    <script>
        document.getElementById('srccode').value = document.getElementById('main').innerHTML
    </script>
</body>
</html>



<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

<title>Comment XSS Test</title>

<script type="text/javascript">
    var my_val = "<?php echo $_GET['a']; ?>";
</script>

</head>
<body>
    <div id="insert">
        In the head, JavaScript sets a URL param to a value. Use param "a".
    </div>
    
</body>
</html>
