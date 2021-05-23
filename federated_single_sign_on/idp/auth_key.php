<?php
	//session_name("2620368ghwahw90w");
	//session_set_cookie_params(0, '/', '.virtual.vm');
	//ini_set('session.cookie_domain', '.virtual.vm');
	session_start();
    if ($_FILES["tgt"]["error"] > 0)
    {
        echo "Error: " . $_FILES["tgt"]["error"] . "<br />";
    }
    else
    {
        /*
            echo "Upload: " . $_FILES["tgt"]["name"] . "<br />";
            echo "Type: " . $_FILES["tgt"]["type"] . "<br />";
            echo "Size: " . ($_FILES["tgt"]["size"]) . " bytes<br />";
            echo "Stored in: " . $_FILES["tgt"]["tmp_name"] . "<br />";
            echo "Content: " . file_get_contents($_FILES["tgt"]["tmp_name"]);
        */
        $tgt = file_get_contents($_FILES["tgt"]["tmp_name"]);
        
        /* Request shared key from Kerberos Server Simulation*/
		$kerberos_port = 50002; // Get the port for the SAML-AAI/Kerbero service.
		$kerberos_ip = gethostbyname('localhost'); // Get the IP address for the target host.

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

		echo "Attempting to connect to '$kerberos_ip' on port '$kerberos_port'...<br>";

		$connect = socket_connect($socket, $kerberos_ip, $kerberos_port);
		
		if ($connect === false)
		{
			echo "socket_connect() failed.<br>Reason: ".socket_strerror(socket_last_error($socket))."<br>";
		}
		else
		{
			echo "OK.<br>";
		}

		$request = "req_st;";
		$request .= $tgt;

		$reply = '';

		//echo "Sending Kerberos shared key request...";
		socket_write($socket, $request, strlen($request));
		//echo "OK.\n";

		//echo "<br>Recieving response...";
		$answer = socket_read($socket, 1024);
		
		if ( $service_key == "fail")
		{
			print "Failed to verify ticket granting ticket";
			socket_close($socket);
		}
		else
		{
			//	request service ticket
			socket_write($socket, "idp", strlen("idp"));	//reqest service ticket for idp
			$service_ticket = socket_read($socket, 1024);
			socket_close($socket);

			$idp_shared_key = $_SESSION["idp_shared_key"];

			$idp_shared_key_info = explode(";", $idp_shared_key);
			
			if ($idp_shared_key_info[3] == $service_ticket)	//compare service ticket and shared key
			{
				$user_info = explode(";", $tgt);
				$_SESSION["username"] = $user_info[0];
				$_SESSION["role"] = $user_info[2];
				$_SESSION["idp_domain"] = $user_info[4];
				
				//	$_SESSION["authenticated"] asserts that the end-user is authenticated
				//	this will be used later to generate assertion
				$_SESSION["authenticated"] = true;

				if (isset($_GET["url"])) 
				{
					$url = $_GET["url"];
				}
				else
				{
					$url = "http://home.virtual.vm/idp/auth_success.php";
				}
				
				header( 'Location: http://home.virtual.vm/idp/auth_success.php' );
			}
			else
			{
				print "failed to verify service ticket<br>";
			}
		}
    }
/*
    $user_info = explode(";", $content);

    // initiate DOMDocument for accessing xml file
	$doc = new DOMDocument();
	$doc->load( 'userdatabase.xml' );

	// get xml element that with the tag:"users".
	$users = $doc->getElementsByTagName( "users" );
	foreach( $users as $user )
	{
		//	get username
		$usernames = $user->getElementsByTagName( "username" );
		$username = $usernames->item(0)->nodeValue;

		//	get password
		$passwords = $user->getElementsByTagName( "password" );
		$password = $passwords->item(0)->nodeValue;

		//	get role
		$roles = $user->getElementsByTagName( "role" );
		$role = $roles->item(0)->nodeValue;
		
		//	assert that the end-user is authenticated
		//	this will be used later to generate assertion
		$authenticateds = $user->getElementsByTagName("authenticated");
		$authenticated = $authenticateds->item(0)->nodeValue;

		//	indicate the domain of the end-user resides in
		$domains = $user->getElementsByTagName( "domain" );
		$domain = $domains->item(0)->nodeValue;
	}
    
    //	loop through all the users
    for ($i=0; $i<($usernames->length); $i++)
    {
        //	if found a matching pair of username and password
        if ($user_info[0] == $usernames->item($i)->nodeValue && 
            $user_info[1] == $passwords->item($i)->nodeValue)
        {
            $_SESSION["username"] = $user_info[0];
            $_SESSION["idp_domain"] = $domains->item($i)->nodeValue;
            $_SESSION["role"] = $roles->item($i)->nodeValue;

            //	$_SESSION["authenticated"] asserts that the end-user is authenticated
            //	this will be used later to generate assertion
            $_SESSION["authenticated"] = true;

            if (isset($_GET["url"])) {
                $url = $_GET["url"];
            }
            else
            {
                $url = "http://localhost/~cliang/idp/auth_success.php";
            }
        }	//	end of if statment for authentication
    }	//	end of $i for loop
    $auth_fail = true;
*/
?>
