<html>
<head>
<title>Service Provider Simulation (foreign.virtual.vm)</title>
</head>
<body>
	<img src="../img/dit_crest_2010.gif"/>
	<img src="../img/dit_logo_2010.gif"/><br><br>
	<center>
		Service Provider Simulation (foreign.virtual.vm)<br><br>

		<?php session_start(); error_reporting(E_ALL);

        /* Request User Provisioning from SAML-AAI/Kerberos*/
        function requestProvision($username, $domain, $permission)
        {
            echo "<b>Requesting Identity Provisioning from SAML-AAI/Kerberos for $username@$domain</b><br>";

            $saml_aai_kerberos_port = 1234; // Get the port for the SAML-AAI/Kerbero service.
            $saml_aai_kerberos_ip = gethostbyname('localhost'); // Get the IP address for the target host.

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

            echo "Attempting to connect to '$saml_aai_kerberos_ip' on port '$saml_aai_kerberos_port'...";
            $connect = socket_connect($socket, $saml_aai_kerberos_ip, $saml_aai_kerberos_port);
            if ($connect === false)
            {
                echo "socket_connect() failed.\nReason: ($result) ".socket_strerror(socket_last_error($socket))."<br>";
            }
            else
            {
                echo "OK.<br>";
            }

            $request = "req_tgt_foreign;";
            $request .= "$username".';';
            $request .= "$domain".';';
            $request .= trim($permission);

            $reply = '';

            echo "Sending user provisioning request...";
            socket_write($socket, $request, strlen($request));
            echo "OK.\n";

            echo "<br>Recieving response...";
            while ($reply = socket_read($socket, 1024))
            {
                socket_close($socket);
                echo "OK.<br><br>";
                return $reply;
            }
        }
        
        /* Request TGT from KDC on behalf of the end-user */
        function S4U2SelfUser($secure)
        {
            echo "<b>Requesting TGT from KDC on behalf of user (S4U2SelfUser)</b><br>";

            $kdc_port = 50001; // Get the port for the SAML-AAI/Kerbero service.
            $kdc_ip = gethostbyname('localhost'); // Get the IP address for the target host.

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

            echo "Attempting to connect to '$kdc_ip' on port '$kdc_port'...";
            
            $connect = socket_connect($socket, $kdc_ip, $kdc_port);
            if ($connect === false)
            {
				$result = socket_strerror(socket_last_error($socket));
                echo "socket_connect() failed.\nReason: ($result)<br>";
            }
            else
            {
                echo "OK.<br>";
            }
            
            $request = "req_tgt;";
            $request .= "$secure";
			
			echo $request;
			
            $reply = '';
            
            echo "Sending request for ticket granting ticket...";
            socket_write($socket, $request, strlen($request));
            echo "OK.\n";

            echo "<br>Recieving ticket granting ticket...";
            while ($reply = socket_read($socket, 1024))
            {
				echo $reply;
                socket_close($socket);
                echo "OK.<br><br>";
                return $reply;
            }
        }
        
        /* Request Service Ticket from KDC on behalf of the end-user*/
        function S4U2SelfProxy($secure)
        {
            echo "<b>Requesting Service Ticket on behalf of user (S4U2SelfProxy)</b><br>";

            $kdc_port = 50001; // Get the port for the SAML-AAI/Kerbero service.
            $kdc_ip = gethostbyname('localhost'); // Get the IP address for the target host.
            
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

            echo "Attempting to connect to '$kdc_ip' on port '$kdc_port'...";
            
            $connect = socket_connect($socket, $kdc_ip, $kdc_port);
            if ($connect === false)
            {
                echo "socket_connect() failed.\nReason: ($result) ".socket_strerror(socket_last_error($socket))."<br>";
            }
            else
            {
                echo "OK.<br>";
            }
            
            $request = "req_st;";
            $request .= "$secure";
            
            $reply = '';
            
            echo "Sending ticket granting ticket...";
            socket_write($socket, $request, strlen($request));
            echo "OK.\n";

            echo "<br>Recieving response...";
            while ($reply = socket_read($socket, 1024))
            {
                echo "OK.<br>";
                if ($reply == 'ok')
                {
                    echo "Sending request for service ticket...";
                    socket_write($socket, 'ssh', strlen('ssh'));
                }
                else
                {
                    echo "Recieving servcie ticket...OK.<br><br>";
                    socket_close($socket);
                    return $reply;
                }
            }
            echo "<br>".$reply."<br>";
        }
        
		try
		{
			$_SESSION["sp_url"] = "http://localhost/~cliang/sp/sp.php";
			$_SESSION["sp_domain"] = "foreign.virtual.vm";
			$sp_domain = $_SESSION["sp_domain"];
			$asserted = false;

			$user = $_COOKIE["user"];
			$user_list = explode(";", $user);
			//echo $user;
			//print_r($_COOKIE);
			
			if($user_list[3] == "authenticated") 
			{
				//echo "true";
				$username = $user_list[0]; //$_SESSION["username"];
				$role = $user_list[1]; //$_SESSION["role"];
				$domain = $user_list[2]; //$_SESSION["idp_domain"];

				$doc = new DOMDocument();
				$doc->load( 'user_policy.xml' );

				$policies = $doc->getElementsByTagName("policy");
				foreach( $policies as $policy )
				{
					$students = $policy->getElementsByTagName("student");
					$student = $students->item(0)->nodeValue;

					$lectures = $policy->getElementsByTagName("lecture");
					$lecture = $lectures->item(0)->nodeValue;
				}
				
				if ($role == "student")
				{
					$permission = $student;
				}
				else if ($role == "lecture")
				{
					$permission = $lecture;
				}

				echo "<font color=\"red\">
				User \"$username\" has been 
				authenticated by the identity provider 
				simulation in domain $domain<br><br>
				\"$username\" is a $role in $domain, 
				therefore, \"$username\" 
				is granted $permission permission in domain $sp_domain
				</font>
				<br><br><br>";
				
				echo "<b>Detail information:</b>
				<table>
					<tr>
						<td>Username:</td>
						<td>$username"."@"."$domain</td>
					</tr>
					<tr>
						<td>Role:</td>
						<td>$permission<td>
					</tr>
				</table>
				<br><br>";
                
                //$secure = requestProvision($username, $domain, $permission);
                $secure = $username.";321";
                $secure_list = explode(";", $secure);
                
                //$auth_info = '';
                //$auth_info .= $secure_list[0].';';
                //$auth_info .= $secure_list[1];
                
                $tgt = S4U2SelfUser($secure);
                $st = S4U2SelfProxy($tgt);

                $_SESSION['st'] = $st;
            ?>

            <b>Go to web-based ssh client simulation</b>
            <form name="gotoapp" method="POST" action="http://localhost/~cliang/sp/app.php">
				<input type="submit" name="submit_button" value="Go"/>
            </form>
            
            <?php session_start();
			}
			else
			{
				echo "<font color=\"red\">
						No assertion has been received from
						identity provider simulation
						</font>
						<br>";
			}
		}
		catch(Exception $e)
		{
			$message = $e->getMessage();
			echo $message;
		}
		?>
        <br><br><br>
		<h2>Select your identity providers from the list:</h2>

		<form name="gotoidp" method="POST" 
			action="http://localhost/~cliang/idp/idp.php">
			<select name="idp_list" size="1" onChange="gotosite()">
				<option value="http://localhost/~cliang/idp/idp.php">
					home.virtual.vm
				</option>
				<input type="submit" name="submit_button" value="Go"/>
			</select>
		</form>
	</center>
	<br><br>
	<a href="../index.php">Back to Index</a><br><br>
</body>
</html>
