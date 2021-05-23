<?php session_start();
    $ssh_port = 2222; // Get the port for the SAML-AAI/Kerbero service.
    $ssh_ip = gethostbyname('localhost'); // Get the IP address for the target host.
    $st_info = $_SESSION['st'];
    $reply = '';
    
    $command = $_GET['command'];

    // Create a TCP/IP socket.
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if ($socket === false)
    {
        echo "socket_create() failed: reason: ".socket_strerror(socket_last_error())."<br>";
    }
   
    $connect = socket_connect($socket, $ssh_ip, $ssh_port);

    if ($connect === false)
    {
        echo "socket_connect() failed.\nReason: ($result) ".socket_strerror(socket_last_error($socket))."\n";
    }
    else
    {
        socket_write($socket, $st_info, strlen($st_info));

        $reply = socket_read($socket, 1024);
        
        if ($reply != "fail")
        {
            $shell_name = $reply;
            
            socket_write($socket, $command, strlen($command));
            $reply = socket_read($socket, 1024);
            
            echo "\n".$reply."\n";

            //socket_write($socket, "exit", strlen("exit"));
           // $reply = socket_read($socket, 1024);
            //socket_close($socket);
            
        }
        else
        {
            echo "\nFail to authenticate service ticket\n";
        }
    }
?>
