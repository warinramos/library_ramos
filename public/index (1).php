<?php 
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

$app = AppFactory::create();

$app->setBasePath('/library/public');

$app->addErrorMiddleware(true, true, true);



//USER REGISTRATION
$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $username = filter_var($data->username, FILTER_SANITIZE_STRING);
    $password = $data->password;

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $username]);
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existingUser) {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Username already taken."]));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $username, 'password' => $hashedPassword]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => "User registered successfully."]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});





//USER AUTHENTICATION
$app->post('/user/authenticate', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $username = filter_var($data->username, FILTER_SANITIZE_STRING);
    $password = $data->password;

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin'; 

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid username or password."]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        $sql = "DELETE FROM used_tokens WHERE userid = :userid AND expires_at < NOW()";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $user['userid']]);

        $iat = time(); 
        $exp = $iat + 3600; 
        $payload = [
            'iss' => 'http://yourdomain.com', 
            'aud' => 'http://yourapp.com',    
            'iat' => $iat,                    
            'exp' => $exp,                    
            'data' => [
                'userid' => $user['userid'],
                'username' => $username
            ]
        ];

        $jwt = JWT::encode($payload, $key, 'HS256');

        $sql = "INSERT INTO used_tokens (userid, token, expires_at) VALUES (:userid, :token, :expires_at)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            'userid' => $user['userid'],
            'token' => $jwt,
            'expires_at' => date('Y-m-d H:i:s', $exp)
        ]);

        $response->getBody()->write(json_encode(["status" => "success", "token" => $jwt]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});



// USER UPDATE
$app->put('/user/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $oldUsername = filter_var($data->old_username, FILTER_SANITIZE_STRING);
    $newUsername = filter_var($data->new_username, FILTER_SANITIZE_STRING);
    $newPassword = $data->new_password;
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the token has already been used
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord) {
            // Check if `used_at` is already set, meaning the token has been used
            if ($tokenRecord['used_at'] !== null) {
                $response->getBody()->write(json_encode([
                    "status" => "fail",
                    "data" => "Token has already been used. Please provide a new token for the next request."
                ]));
                return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
            }

            // Mark token as used by updating `used_at`
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Invalid token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        $sql = "SELECT * FROM users WHERE username = :old_username";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['old_username' => $oldUsername]);
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existingUser) {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "User not found"]));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        $userid = $existingUser['userid'];

        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        $sql = "UPDATE users SET username = :new_username, password = :password WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            'new_username' => $newUsername,
            'password' => $hashedPassword,
            'userid' => $userid
        ]);

        $response->getBody()->write(json_encode([
            "status" => "success",
            "data" => "User updated successfully"
        ]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});



// DELETE USER
$app->delete('/user/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $username = filter_var($data->username, FILTER_SANITIZE_STRING);
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);

    $key = getenv('JWT_SECRET') ?: 'warin';

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    try {
        $decoded = \Firebase\JWT\JWT::decode($token, new \Firebase\JWT\Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the token has already been used
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord) {
            // Check if `used_at` is already set, meaning the token has been used
            if ($tokenRecord['used_at'] !== null) {
                $response->getBody()->write(json_encode([
                    "status" => "fail",
                    "data" => "Token has already been used. Please provide a new token for the next request."
                ]));
                return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
            }

            // Mark token as used by updating `used_at`
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Invalid token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Fetch the user to be deleted
        $sql = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $username]);
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existingUser) {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "User not found"]));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        $userid = $existingUser['userid'];

        // Delete the user's tokens
        $sql = "DELETE FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);

        // Delete the user
        $sql = "DELETE FROM users WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => "User deleted successfully"]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});






// DISPLAY USER
$app->post('/user/display', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $username = filter_var($data->username, FILTER_SANITIZE_STRING);
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = \Firebase\JWT\JWT::decode($token, new \Firebase\JWT\Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the token has already been used
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord) {
            // Check if `used_at` is already set, meaning the token has been used
            if ($tokenRecord['used_at'] !== null) {
                $response->getBody()->write(json_encode([
                    "status" => "fail",
                    "data" => "Token has already been used. Please provide a new token for the next request."
                ]));
                return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
            }

            // Mark token as used by updating `used_at`
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Invalid token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Fetch the user information
        $sql = "SELECT users.userid, users.username, users.password
                FROM users
                WHERE users.username = :username";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "User not found"]));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        $response->getBody()->write(json_encode(["status" => "success", "data" => $user]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});





// ADD BOOKS
$app->post('/book/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $title = filter_var($data->title, FILTER_SANITIZE_STRING);
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Insert the book if not exists
        $sql = "SELECT * FROM books WHERE title = :title";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['title' => $title]);
        $existingBook = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existingBook) {
            $sql = "INSERT INTO books (title) VALUES (:title)";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['title' => $title]);
            $bookid = $conn->lastInsertId();
        } else {
            $bookid = $existingBook['bookid'];
        }

        $response->getBody()->write(json_encode(["status" => "success", "data" => "Book added successfully", "bookid" => $bookid]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});




// UPDATE BOOK
$app->post('/book/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);
    $bookid = filter_var($data->bookid, FILTER_SANITIZE_NUMBER_INT); // Book ID to update
    $title = filter_var($data->title, FILTER_SANITIZE_STRING); // New title

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Update book title
        $sql = "UPDATE books SET title = :title WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['title' => $title, 'bookid' => $bookid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => "Book updated successfully"]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});





// DELETE BOOK
$app->post('/book/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);
    $bookid = filter_var($data->bookid, FILTER_SANITIZE_NUMBER_INT);

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Delete the book
        $sql = "DELETE FROM books WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['bookid' => $bookid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => "Book deleted successfully"]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});



// DISPLAY ALL BOOKS
$app->post('/book/display', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Display all books
        $sql = "SELECT bookid, title FROM books";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $response->getBody()->write(json_encode(["status" => "success", "data" => $books]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null;
});




// ADD AUTHOR
$app->post('/author/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $name = filter_var($data->name, FILTER_SANITIZE_STRING);
    $token = filter_var($data->token, FILTER_SANITIZE_STRING); 

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Check for existing author
        $sql = "SELECT * FROM authors WHERE name = :name";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['name' => $name]);
        $existingAuthor = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existingAuthor) {
            // Add new author
            $sql = "INSERT INTO authors (name) VALUES (:name)";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['name' => $name]);
            $authorid = $conn->lastInsertId();
        } else {
            $authorid = $existingAuthor['authorid'];
        }

        $response->getBody()->write(json_encode(["status" => "success", "data" => "Author added successfully", "authorid" => $authorid]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null; 
});





// DELETE AUTHOR
$app->post('/author/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $authorid = filter_var($data->authorid, FILTER_SANITIZE_NUMBER_INT);
    $token = filter_var($data->token, FILTER_SANITIZE_STRING); 

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Delete author
        $sql = "DELETE FROM authors WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['authorid' => $authorid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => "Author deleted successfully"]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null; 
});




// UPDATE AUTHOR
$app->post('/author/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $authorid = filter_var($data->authorid, FILTER_SANITIZE_NUMBER_INT);
    $name = filter_var($data->name, FILTER_SANITIZE_STRING);
    $token = filter_var($data->token, FILTER_SANITIZE_STRING); 

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Update author name
        $sql = "UPDATE authors SET name = :name WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['name' => $name, 'authorid' => $authorid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => "Author updated successfully"]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null; 
});






// DISPLAY ALL AUTHORS
$app->post('/author/display', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $token = filter_var($data->token, FILTER_SANITIZE_STRING); 

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Display authors
        $sql = "SELECT authorid, name FROM authors";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $response->getBody()->write(json_encode(["status" => "success", "data" => $authors]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null; 
});





// ADD BOOK-AUTHOR ASSOCIATION
$app->post('/books_authors/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $bookid = filter_var($data->bookid, FILTER_SANITIZE_NUMBER_INT);
    $authorid = filter_var($data->authorid, FILTER_SANITIZE_NUMBER_INT);
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin'; 

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        $sql = "INSERT INTO books_authors (bookid, authorid) VALUES (:bookid, :authorid)";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['bookid' => $bookid, 'authorid' => $authorid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => "Book-Author association added successfully."]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null; 
});




// DELETE BOOK-AUTHOR ASSOCIATION
$app->delete('/books_authors/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $collectionid = filter_var($data->collectionid, FILTER_SANITIZE_NUMBER_INT);
    $token = filter_var($data->token, FILTER_SANITIZE_STRING);

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin'; 

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        $sql = "DELETE FROM books_authors WHERE collectionid = :collectionid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['collectionid' => $collectionid]);

        $response->getBody()->write(json_encode(["status" => "success", "data" => "Book-Author association deleted successfully."]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null; 
});





// DISPLAY ALL BOOK-AUTHOR ASSOCIATIONS
$app->get('/books_authors/display', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $token = filter_var($data->token, FILTER_SANITIZE_STRING);

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = getenv('JWT_SECRET') ?: 'warin'; 

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Token verification
        $sql = "SELECT * FROM used_tokens WHERE token = :token";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $token]);
        $tokenRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($tokenRecord && $tokenRecord['used_at'] !== null) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => "Token has already been used. Please provide a new token."
            ]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Mark token as used
        if ($tokenRecord) {
            $sql = "UPDATE used_tokens SET used_at = NOW() WHERE token = :token";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $token]);
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => "Invalid token."]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        $sql = "SELECT * FROM books_authors";
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        $associations = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $response->getBody()->write(json_encode(["status" => "success", "data" => $associations]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => "Unexpected error occurred: " . $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    $conn = null; 
});




$app->run();
