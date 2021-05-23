<html>
<head>
<title>SSH Client Simulation</title>
<script language="javascript" type="text/javascript">
<!-- 
//Browser Support Code
function ajaxFunction() {
	var ajaxRequest;  // The variable that makes Ajax possible!
	
	try {
		// Opera 8.0+, Firefox, Safari
		ajaxRequest = new XMLHttpRequest();
    } 
    catch(e) {
        // Internet Explorer Browsers
        try {
            ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");
        } 
        catch(e) {
            try {
                ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");
            } 
            catch(e) {
                // Something went wrong
                alert("Your browser broke!");
                return false;
            }
        }
    }
    
    // Create a function that will receive data sent from the server
    ajaxRequest.onreadystatechange = function(){
        if(ajaxRequest.readyState == 4){
            document.SSHSIM.output.value = ajaxRequest.responseText;
        }
    }
    var command = document.getElementById('command').value;
    if(command!="exit")
    {
        var queryString = "?command=" + command;

        ajaxRequest.open("GET", "io.php" + queryString, true);
        ajaxRequest.send(null);
    }
    else
    {
        top.location.href="sp.php";
    }
}
//-->
</script>
</head>
<body>
<?php session_start();
    echo "<b>SSH Client Simulation that lists all the files</b><br>";

    $ssh_port = 2222; // Get the port for the SAML-AAI/Kerbero service.
    $ssh_ip = gethostbyname('localhost'); // Get the IP address for the target host.
    $st_info = $_SESSION['st'];
    $reply = '';

    /* Create a TCP/IP socket. */
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if ($socket === false)
    {
        echo "socket_create() failed: reason: ".socket_strerror(socket_last_error())."<br>";
    }
    else
    {
        echo "Creating Socket...OK.<br>";
    }

    echo "Attempting to connect to '$ssh_ip' on port '$ssh_port'...";

    $connect = socket_connect($socket, $ssh_ip, $ssh_port);
    if ($connect === false)
    {
		$result = socket_strerror(socket_last_error($socket));
        echo "<br>socket_connect() failed.<br>Reason: $result<br>";
    }
    else
    {
        echo "OK.<br>";
        echo "Sending service ticket...";
        socket_write($socket, $st_info, strlen($st_info));
        echo "OK.<br>";

        $reply = socket_read($socket, 1024);
        
        if ($reply != "fail")
        {
            $shell_name = $reply;
            //socket_write($socket, "ls", strlen("ls"));
            ?>
            
            <form name='SSHSIM'>
                <font color="blue"> <?php session_start(); echo $shell_name ?>
                <input type = "text" id = "command" onChange="ajaxFunction();"/><br>
                <textarea rows="20" cols="80" readonly="readonly" name="output"></textarea>
                </font>
            </form>
            
            <?php session_start();

        }
        else
        {
            echo "<br>Fail to authenticate service ticket<br>";
        }
        echo "<br><br>Back to service provider<br>
            <form name=\"gotosp\" method=\"POST\" action=\"http://localhost/~cliang/sp/sp.php\">
                <input type=\"submit\" name=\"submit_button\" value=\"Go\"/>
            </form>";
    }
?>


<br><br>
	<a href="../index.php">Back to Index</a><br><br>
</body>
</html>
