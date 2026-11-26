<?php
/**
 * Tobi AIM - Zero-Trust API Gateway V3
 * Dispatches requests to compiled `serverkey_core` (daemon/CLI) with CoreEngine PHP ext-sodium fallback.
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/CoreEngine.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$rawBody = file_get_contents('php://input');
if ($rawBody === false || strlen($rawBody) > 65536 || trim($rawBody) === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request size or empty body']);
    exit;
}

$payload = json_decode($rawBody, true);
if (!is_array($payload)) {
    http_response_code(400);
    echo json_encode(['error' => 'Malformed JSON payload']);
    exit;
}

$action = trim((string)($_GET['action'] ?? 'v3'));
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$payload['client_ip'] = $clientIp;

/**
 * Tries local compiled Rust daemon (`serverkey_core --serve`) or CLI binary (`--exec`).
 */
function dispatchToRustCore(string $action, array $payload): ?array {
    $mode = strtolower(envValue('RUST_CORE_MODE', 'auto'));
    if ($mode === 'php' || $mode === 'off') {
        return null;
    }

    $jsonPayload = json_encode($payload, JSON_UNESCAPED_SLASHES);
    $ipcSecret = envValue('RUST_CORE_IPC_SECRET', '');
    $rustUrl = envValue('RUST_CORE_URL', 'http://127.0.0.1:8787');
    $path = ($action === 'ci_register_build') ? '/ci_register_build' : '/v3';

    // 1. Try local Rust HTTP daemon if configured
    if (($mode === 'daemon' || $mode === 'auto') && function_exists('curl_init') && $rustUrl !== '') {
        $ch = @curl_init(rtrim($rustUrl, '/') . $path);
        if ($ch) {
            $headers = ['Content-Type: application/json'];
            if ($ipcSecret !== '') {
                $headers[] = 'X-Core-Ipc-Sig: ' . hash_hmac('sha256', $jsonPayload, $ipcSecret);
            }
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $jsonPayload,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT_MS => 300,
                CURLOPT_TIMEOUT => 4,
            ]);
            $res = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($res !== false && $code > 0) {
                $decoded = json_decode($res, true);
                if (is_array($decoded)) {
                    return [$code, $decoded];
                }
            }
        }
    }

    // 2. Try compiled CLI binary via proc_open
    $bin = envValue('RUST_CORE_BIN', '');
    if ($bin !== '' && @is_executable($bin) && function_exists('proc_open')) {
        $cmdInput = json_encode(['action' => $action, 'payload' => $payload], JSON_UNESCAPED_SLASHES);
        $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = @proc_open($bin . ' --exec', $spec, $pipes, __DIR__);
        if (is_resource($proc)) {
            fwrite($pipes[0], $cmdInput);
            fclose($pipes[0]);
            $out = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
            $decoded = json_decode((string)$out, true);
            if (is_array($decoded) && isset($decoded['http_status'], $decoded['body'])) {
                return [intval($decoded['http_status']), $decoded['body']];
            }
        }
    }

    if ($mode === 'daemon' || $mode === 'cli') {
        return [503, ['error' => 'Core security service unavailable']];
    }
    return null;
}

try {
    if (!in_array($action, ['v3', 'ci_register_build'], true)) {
        http_response_code(404);
        echo json_encode(['error' => 'Unsupported endpoint']);
        exit;
    }

    $rustResult = dispatchToRustCore($action, $payload);
    if ($rustResult !== null) {
        [$statusCode, $body] = $rustResult;
    } else {
        $engine = new CoreEngine();
        [$statusCode, $body] = ($action === 'ci_register_build')
            ? $engine->handleCiRegisterBuild($payload)
            : $engine->handleV3($payload, $clientIp);
    }

    http_response_code($statusCode);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    error_log('api_v2 failure: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Internal security processing error']);
}
