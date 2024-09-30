<?php
include 'db-connection.php';
session_start();

$username = $_POST['username'];
$password = $_POST['password'];

if(verifyCredentials($username,$password)) {
    $_SESSION['username'] = $username;
    header("Location: index.html");
}else{
    header("Location: login.html?error=Invalid credentials");
}
function verifyCredentials($username,$password){
    global $conn;

    $stmt = $conn->prepare("SELECT * FROM user WHERE username = ?");
    $stmt->bind_param("s",$username);
    $stmt->execute();
    $result = $stmt->get_result();

    if($result->num_rows===1){
        $row=$result->fetch_assoc();
        if(password_verify($password,$row['password'])){
            return true;
        }
    }
    return false;
}
?>