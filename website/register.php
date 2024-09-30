<?php
include 'db-connection.php';
session_start();
$username = $_POST['username'];
$password = $_POST['password'];

if (insertUser($username,$password)) {

echo 'User created';
die;
}

else
{
echo 'user creation railed';
die;
}
$_SESSION['username'] = $username;
header("Location: index.html?error=Registration failed");

function insertUser($username,$password){
global $conn;
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

$stmt = $conn->prepare("INSERT INTO user (username, password)VALUES(?, ?)");
$stmt->bind_param("ss",$username, $hashedPassword);

return $stmt->execute();
}
?>