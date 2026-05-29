<?php
/**
 * API Backend
 * 
 * Usage:
 *   api.php                     — All tweets (sorted by confidence)
 *   api.php?search=nginx        — Search by text/author/CVE/hashtag
 *   api.php?cve=CVE-2026        — Filter by CVE
 *   api.php?hashtag=bugbounty   — Filter by hashtag
 *   api.php?author=hetmehtaa    — Filter by author handle
 *   api.php?min_score=0.5       — Minimum confidence score
 *   api.php?min_award=1000      — Minimum award amount
 *   api.php?sort=score|date|likes|award
 *   api.php?limit=10            — Max results
 *   api.php?offset=0            — Pagination offset
 *   api.php?stats=1             — Return statistics instead of tweets
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ─── Config ────────────────────────────────────────────────────────────
$db_path = __DIR__ . '/data/sentinel.db';

if (!file_exists($db_path)) {
    http_response_code(404);
    echo json_encode(['error' => 'Database not found. Run: python cli.py init && python cli.py run --once']);
    exit;
}

try {
    $db = new SQLite3($db_path);
    $db->enableExceptions(true);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// ─── Parse parameters ──────────────────────────────────────────────────
$search   = isset($_GET['search'])   ? trim($_GET['search'])   : '';
$cve      = isset($_GET['cve'])      ? trim($_GET['cve'])      : '';
$hashtag  = isset($_GET['hashtag'])  ? trim($_GET['hashtag'])  : '';
$author   = isset($_GET['author'])   ? trim($_GET['author'])   : '';
$min_score = isset($_GET['min_score']) ? floatval($_GET['min_score']) : 0;
$min_award = isset($_GET['min_award']) ? floatval($_GET['min_award']) : 0;
$sort     = isset($_GET['sort'])     ? $_GET['sort']           : 'score';
$limit    = isset($_GET['limit'])    ? min(intval($_GET['limit']), 200) : 200;
$offset   = isset($_GET['offset'])   ? intval($_GET['offset']) : 0;
$stats    = isset($_GET['stats'])    ? intval($_GET['stats'])   : 0;

// ─── Build query ───────────────────────────────────────────────────────
$where = [];
$params = [];

if ($search !== '') {
    $where[] = '(LOWER(author_handle) LIKE :search1 OR LOWER(author_display_name) LIKE :search2 OR LOWER(text) LIKE :search3 OR LOWER(hashtags) LIKE :search4 OR LOWER(cve_ids) LIKE :search5)';
    $s = '%' . strtolower($search) . '%';
    $params[':search1'] = $s;
    $params[':search2'] = $s;
    $params[':search3'] = $s;
    $params[':search4'] = $s;
    $params[':search5'] = $s;
}

if ($cve !== '') {
    $where[] = 'LOWER(cve_ids) LIKE :cve';
    $params[':cve'] = '%' . strtolower($cve) . '%';
}

if ($hashtag !== '') {
    $where[] = 'LOWER(hashtags) LIKE :hashtag';
    $params[':hashtag'] = '%' . strtolower($hashtag) . '%';
}

if ($author !== '') {
    $where[] = 'LOWER(author_handle) = :author';
    $params[':author'] = strtolower($author);
}

if ($min_score > 0) {
    $where[] = 'confidence_score >= :min_score';
    $params[':min_score'] = $min_score;
}

if ($min_award > 0) {
    $where[] = '(award_amount IS NOT NULL AND award_amount >= :min_award)';
    $params[':min_award'] = $min_award;
}

$where_clause = count($where) ? 'WHERE ' . implode(' AND ', $where) : '';

switch ($sort) {
    case 'date':  $order = 'timestamp DESC'; break;
    case 'likes': $order = 'like_count DESC'; break;
    case 'award': $order = 'award_amount DESC NULLS LAST'; break;
    default:      $order = 'confidence_score DESC';
}

// ─── Stats mode ────────────────────────────────────────────────────────
if ($stats) {
    $stats_query = "SELECT COUNT(*) as total, AVG(confidence_score) as avg_score, MAX(award_amount) as max_award, COUNT(CASE WHEN award_amount IS NOT NULL THEN 1 END) as with_award, COUNT(CASE WHEN cve_ids != '[]' THEN 1 END) as with_cve, COUNT(DISTINCT author_handle) as unique_authors FROM tweets $where_clause";
    $result = $db->query($stats_query);
    echo json_encode($result->fetchArray(SQLITE3_ASSOC));
    $db->close();
    exit;
}

// ─── Fetch tweets ──────────────────────────────────────────────────────
$stmt = $db->prepare("SELECT * FROM tweets $where_clause ORDER BY $order LIMIT :limit OFFSET :offset");
$stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
$stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);
foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v);
}

$result = $stmt->execute();
$tweets = [];

while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    // Parse JSON fields
    foreach (['hashtags', 'links', 'media_urls', 'cve_ids'] as $field) {
        if (isset($row[$field]) && is_string($row[$field])) {
            $row[$field] = json_decode($row[$field], true) ?? [];
        }
    }
    // Cast numeric fields
    $row['has_image'] = (int)$row['has_image'];
    $row['has_video'] = (int)$row['has_video'];
    $row['like_count'] = (int)$row['like_count'];
    $row['retweet_count'] = (int)$row['retweet_count'];
    $row['reply_count'] = (int)$row['reply_count'];
    $row['is_thread'] = (int)$row['is_thread'];
    $row['confidence_score'] = (float)$row['confidence_score'];
    $row['award_amount'] = $row['award_amount'] !== null ? (float)$row['award_amount'] : null;

    $tweets[] = $row;
}

// ─── Count total (without limit) ────────────────────────────────────────
$count_stmt = $db->prepare("SELECT COUNT(*) as cnt FROM tweets $where_clause");
foreach ($params as $k => $v) {
    $count_stmt->bindValue($k, $v);
}
$count_result = $count_stmt->execute();
$total = $count_result->fetchArray(SQLITE3_ASSOC)['cnt'] ?? 0;

$db->close();

// ─── Response ──────────────────────────────────────────────────────────
echo json_encode([
    'total' => (int)$total,
    'returned' => count($tweets),
    'offset' => $offset,
    'limit' => $limit,
    'tweets' => $tweets,
], JSON_UNESCAPED_UNICODE);
