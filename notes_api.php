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
    case 'create_note':
        createNote($pdo);
        break;
    case 'get_notes':
        getNotes($pdo);
        break;
    case 'get_note':
        getNote($pdo);
        break;
    case 'update_note':
        updateNote($pdo);
        break;
    case 'delete_note':
        deleteNote($pdo);
        break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
        break;
}

// Получаем ID пользователя из токена
function getUserIdFromToken($pdo): ?int {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        return null;
    }
    $token = $matches[1];
    $stmt = $pdo->prepare("SELECT user_id FROM tokens WHERE token = ?");
    $stmt->execute([$token]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ? $row['user_id'] : null;
}

// Создать заметку
function createNote($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $data = json_decode(file_get_contents('php://input'), true);
    $title = $data['title'] ?? '';
    $content = $data['content'] ?? '';

    if (!$title) {
        http_response_code(400);
        echo json_encode(['error' => 'Title is required']);
        return;
    }

    $stmt = $pdo->prepare("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)");
    try {
        $stmt->execute([$user_id, $title, $content]);
        $note_id = $pdo->lastInsertId();
        http_response_code(200);
        echo json_encode(['success' => 'Note created', 'note_id' => $note_id]);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to create note: ' . $e->getMessage()]);
    }
}

// Получить все заметки
function getNotes($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $stmt = $pdo->prepare("SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $notes = $stmt->fetchAll(PDO::FETCH_ASSOC);

    http_response_code(200);
    echo json_encode(['notes' => $notes]);
}

// Получить одну заметку
function getNote($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $note_id = $_GET['note_id'] ?? null;
    if (!$note_id) {
        http_response_code(400);
        echo json_encode(['error' => 'Note ID is required']);
        return;
    }

    $stmt = $pdo->prepare("SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?");
    $stmt->execute([$note_id, $user_id]);
    $note = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$note) {
        http_response_code(404);
        echo json_encode(['error' => 'Note not found']);
        return;
    }

    http_response_code(200);
    echo json_encode(['note' => $note]);
}

// Обновить заметку
function updateNote($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $note_id = $_GET['note_id'] ?? null;
    $data = json_decode(file_get_contents('php://input'), true);
    $title = $data['title'] ?? null;
    $content = $data['content'] ?? null;

    if (!$note_id || !$title) {
        http_response_code(400);
        echo json_encode(['error' => 'Note ID and title are required']);
        return;
    }

    $stmt = $pdo->prepare("UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?");
    try {
        $stmt->execute([$title, $content, $note_id, $user_id]);
        http_response_code(200);
        echo json_encode(['success' => 'Note updated']);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to update note: ' . $e->getMessage()]);
    }
}

// Удалить заметку
function deleteNote($pdo) {
    $user_id = getUserIdFromToken($pdo);
    if (!$user_id) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $note_id = $_GET['note_id'] ?? null;
    if (!$note_id) {
        http_response_code(400);
        echo json_encode(['error' => 'Note ID is required']);
        return;
    }

    $stmt = $pdo->prepare("DELETE FROM notes WHERE id = ? AND user_id = ?");
    try {
        $stmt->execute([$note_id, $user_id]);
        http_response_code(200);
        echo json_encode(['success' => 'Note deleted']);
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to delete note: ' . $e->getMessage()]);
    }
}