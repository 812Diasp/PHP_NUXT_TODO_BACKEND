<?php
header('Content-Type: application/json');

// Упрощённые CORS-заголовки
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (preg_match('#^https?://localhost(:\d+)?$#', $origin) ||
    preg_match('#^https?://127\.0\.0\.1(:\d+)?$#', $origin)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}


// Подключение к базе данных
$host = 'localhost';
$dbname = 'calendar_db';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(404);
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// Роутинг по параметру ?action=
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'register':
        registerUser($pdo);
        break;
    case 'login':
        loginUser($pdo);
        break;
    case 'add_event':
        addEvent($pdo);
        break;
    case 'get_events':
        getEvents($pdo);
        break;
    case 'delete_event':
        deleteEvent($pdo);
        break;
    case 'filter_events':
        filterEvents($pdo);
        break;
    case 'edit_events':
        editEvent($pdo);
    case 'logout':
        logoutUser($pdo);
        break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
        break;
}

function logoutUser($pdo) {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if(!preg_match('/Bearer\s(\S+)/', $authHeader,$matches)){
        http_response_code(401);
        echo json_encode(['error'=> 'Unauthorised']);
    }
    $token = $matches[1];

    $stmt = $pdo->prepare('DELETE FROM tokens where token = ?');
    $stmt->execute([$token]);

    http_response_code(200);
    echo json_encode(['success'=> 'Logget out succesccfully']);
}
// === УТИЛИТЫ ===

function getUserIdFromToken($pdo): ?int {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        return null;
    }
    $token = $matches[1];

    // Получаем данные токена
    $stmt = $pdo->prepare("SELECT user_id, expires_at FROM tokens WHERE token = ?");
    $stmt->execute([$token]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return null;
    }

    $expiresAt = new DateTime($row['expires_at']);
    $now = new DateTime();

    // Определяем, пора ли обновлять токен (например, если до истечения < 24 часа)
    $interval = $now->diff($expiresAt);
    $remainingMinutes = ($interval->days * 24 * 60) + ($interval->h * 60) + $interval->i;

    if ($remainingMinutes < 60) { // меньше часа до истечения
        // Генерируем новый токен
        $newToken = bin2hex(random_bytes(32));
        $newExpiresAt = date('Y-m-d H:i:s', strtotime('+4 days'));

        // Обновляем запись в БД
        $pdo->prepare("UPDATE tokens SET token = ?, expires_at = ? WHERE token = ?")
           ->execute([$newToken, $newExpiresAt, $token]);

        // Добавляем новый токен в заголовок или тело ответа
        header("X-New-Token: $newToken");
        header("X-Token-Expires-In: " . $newExpiresAt);
    }

    return $row['user_id'];
}

// === ЭНДПОИНТЫ ===

function registerUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    $email = $data['email'] ?? null;

    if (!$username || !$password) {
        http_response_code(400);
        echo json_encode(['error' => 'Username and password are required']);
        return;
    }

    $password_hash = password_hash($password, PASSWORD_BCRYPT);

    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)");
    try {
        $stmt->execute([$username, $password_hash, $email]);
        http_response_code(200);
        echo json_encode(['success' => 'User registered successfully']);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to register user: ' . $e->getMessage()]);
    }
}

function loginUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    if (!$username || !$password) {
        http_response_code(400);
        echo json_encode(['error' => 'Username and password are required']);
        return;
    }

    $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user['password_hash'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid username or password']);
        return;
    }

    $token = bin2hex(random_bytes(32));
    $expires_at = date('Y-m-d H:i:s', strtotime('+4 days'));

    $stmt = $pdo->prepare("INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
    $stmt->execute([$user['id'], $token, $expires_at]);
    http_response_code(200);
    echo json_encode(['token' => $token, 'expires_at' => $expires_at]);
}

function addEvent($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $data = json_decode(file_get_contents('php://input'), true);
    $category_id = $data['category_id'] ?? null;
    $title = $data['title'] ?? null;
    $description = $data['description'] ?? null;
    $event_date = $data['event_date'] ?? null;

    if (!$category_id || !$title || !$event_date) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields']);
        return;
    }

    $stmt = $pdo->prepare("INSERT INTO events (user_id, category_id, title, description, event_date) VALUES (?, ?, ?, ?, ?)");
    try {
        $stmt->execute([$user_id, $category_id, $title, $description, $event_date]);
        http_response_code(200);
        echo json_encode(['success' => 'Event added successfully']);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to add event: ' . $e->getMessage()]);
    }
}

function getEvents($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $stmt = $pdo->prepare("SELECT e.id, e.title, e.description, e.event_date, c.name AS category_name 
                           FROM events e 
                           JOIN categories c ON e.category_id = c.id 
                           WHERE e.user_id = ?");
    $stmt->execute([$user_id]);
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
    http_response_code(200);
    echo json_encode(['events' => $events]);
}

function deleteEvent($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $event_id = $_GET['event_id'] ?? null;

    if (!$event_id) {
        http_response_code(400);
        echo json_encode(['error' => 'Event ID is required']);
        return;
    }

    $stmt = $pdo->prepare("DELETE FROM events WHERE id = ? AND user_id = ?");
    try {
        $stmt->execute([$event_id, $user_id]);
        http_response_code(200);
        echo json_encode(['success' => 'Event deleted successfully']);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to delete event: ' . $e->getMessage()]);
    }
}

function filterEvents($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $category_id = $_GET['category_id'] ?? null;
    $query = "SELECT e.id, e.title, e.description, e.event_date, c.name AS category_name 
              FROM events e 
              JOIN categories c ON e.category_id = c.id 
              WHERE e.user_id = ?";
    $params = [$user_id];

    if ($category_id) {
        $query .= " AND e.category_id = ?";
        $params[] = $category_id;
    }

    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
    http_response_code(200);
    echo json_encode(['events' => $events]);
}
//дорелизовать в фронте
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
function editEvent($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $event_id = $_GET['event_id'] ?? null;
    $data = json_decode(file_get_contents('php://input'), true);

    if (!$event_id || !$data['title'] || !$data['category_id'] || !$data['event_date']) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields']);
        return;
    }

    $stmt = $pdo->prepare("UPDATE events SET
        title = ?,
        description = ?,
        category_id = ?,
        event_date = ?
        WHERE id = ? AND user_id = ?");

    try {
        $stmt->execute([
            $data['title'],
            $data['description'] ?? null,
            $data['category_id'],
            $data['event_date'],
            $event_id,
            $user_id
        ]);
        http_response_code(200);
        echo json_encode(['success' => 'Event updated successfully']);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to update event: ' . $e->getMessage()]);
    }
}
