<?php
session_start();

// Check if user is already logged in, redirect to profile page
if(isset($_SESSION['user_id'])){
    header("Location: profile.php");
    exit;
}

// Check if form is submitted
if(isset($_POST['submit'])){

    // Include database connection
    require_once 'db_connection.php';

    // Sanitize user input
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = filter_var($_POST['password'], FILTER_SANITIZE_STRING);

    // Validate user input
    $error = false;
    $errorMsg = "";
    if(empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)){
        $error = true;
        $errorMsg .= "Invalid email format.<br>";
    }
    if(empty($password)){
        $error = true;
        $errorMsg .= "Password is required.<br>";
    }

    // If input is valid, check if user exists in database
    if(!$error){
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        // If user exists, check if password is correct
        if($result->num_rows == 1){
            $row = $result->fetch_assoc();
            if(password_verify($password, $row['password'])){
                // Password is correct, set session variables and redirect to profile page
                $_SESSION['user_id'] = $row['id'];
                header("Location: profile.php");
                exit;
            } else {
                // Password is incorrect
                $errorMsg .= "Incorrect password.<br>";
            }
        } else {
            // User does not exist
            $errorMsg .= "User does not exist.<br>";
        }
    }

    // If there are errors, display error message
    if($error){
        echo '<div class="alert alert-danger">'.$errorMsg.'</div>';
    }

    // Close database connection
    $stmt->close();
    $conn->close();
}
?>
