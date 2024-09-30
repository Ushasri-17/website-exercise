
<?php
session_start();


if (isset($_SESSION['user'])) {
    // Unset all of the session variables
    unset($_SESSION['user']);

    // Set message
    // Redirect to login page
    redirect('login.php', "You have been logged out successfully.");
}

// Redirect to the login page without message
header("Location: login.php");
exit;
?>
