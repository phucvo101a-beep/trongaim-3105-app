<?php
/**
 * Tobi AIM - V3 Cryptographic Auth Engine (PHP ext-sodium fallback matching serverkey_core Rust)
 */

final class CoreEngine {
    public const BUNDLED_PRESETS = [
        'AIM BODY FFVN (1).3105',
        'Aim_Neck_TobiAim_FFVN.3105',
        'AimDrag_85_Antena_TobiAim_FFVN.3105',
        'AimDrag_85_TobiAim_FFVN.3105',
        'AimNeck_Antena_TobiAim_FFVN.3105',
        'Antena_TobiAim_FFVN.3105',
        'DinhVi_Chams_TobiAim_FFVN.3105',
        'DinhVi_Sung_TobiAim_FFVN.3105',
        'MODSKIN FFVN PHUCVN (1).3105',
        'MODSKIN FFVN PHUCVN (2).3105',
        'MODSKIN FFVN PHUCVN (3).3105',
        'MODSKIN FFVN PHUCVN (4).3105',
        'MODSKIN FFVN PHUCVN (5).3105',
    ];

    public const PRESET_LABELS = [
        'AIM BODY FFVN (1).3105' => 'AIM BODY',
        'Aim_Neck_TobiAim_FFVN.3105' => 'AIM NECK',
        'AimDrag_85_Antena_TobiAim_FFVN.3105' => 'AIM DRAG ANTENA',
        'AimDrag_85_TobiAim_FFVN.3105' => 'DRAG 85%',
        'AimNeck_Antena_TobiAim_FFVN.3105' => 'AIM NECK ANTENA',
        'Antena_TobiAim_FFVN.3105' => 'ANTENA',
        'DinhVi_Chams_TobiAim_FFVN.3105' => 'CHAMS',
        'DinhVi_Sung_TobiAim_FFVN.3105' => 'DINHVI SUNG KEO',
        'MODSKIN FFVN PHUCVN (1).3105' => 'MODSKIN 1',
        'MODSKIN FFVN PHUCVN (2).3105' => 'MODSKIN 2',
        'MODSKIN FFVN PHUCVN (3).3105' => 'MODSKIN 3',
        'MODSKIN FFVN PHUCVN (4).3105' => 'MODSKIN 4',
        'MODSKIN FFVN PHUCVN (5).3105' => 'MODSKIN 5',
    ];

    public static function resolvePresetPolicies(array $settings): array {
        $raw = (isset($settings['preset_policies']) && is_array($settings['preset_policies']))
            ? $settings['preset_policies']
            : [];
        $out = [];
        foreach (self::BUNDLED_PRESETS as $fname) {
            $bidHex = bin2hex(substr(hash('sha256', 'BUNDLE|' . $fname, true), 0, 16));
            $cfg = (isset($raw[$fname]) && is_array($raw[$fname])) ? $raw[$fname] : [];
            $status = strtolower(trim((string)($cfg['status'] ?? 'stable'))) === 'maintenance'
                ? 'maintenance'
                : 'stable';
            $msg = trim((string)($cfg['message'] ?? ''));
            if ($status === 'maintenance' && $msg === '') {
                $msg = 'File mod này đang được bảo trì để cập nhật. Vui lòng dùng tính năng khác hoặc quay lại sau.';
            }
            $out[$bidHex] = [
                'bundle_id' => $bidHex,
                'file_name' => $fname,
                'label' => self::PRESET_LABELS[$fname] ?? $fname,
                'status' => $status,
                'message' => $msg,
            ];
        }
        return $out;
    }

    private const MAX_CLOCK_SKEW = 180;

    private string $x25519Priv;
    private string $ed25519Seed;
    private string $pepper;
    private string $bundleMasterKey;
    private string $ciSyncSecret;

    public function __construct() {
        $xHex = envValue('SERVER_X25519_PRIV_HEX');
        $eHex = envValue('SERVER_ED25519_PRIV_HEX');
        $bHex = envValue('BUNDLE_PATCH_MASTER_KEY_HEX');
        $this->pepper = envValue('PRE_SHARED_PEPPER');
        $this->ciSyncSecret = envValue('CI_SYNC_SECRET');

        if (strlen($xHex) !== 64 || strlen($eHex) !== 64 || strlen($bHex) !== 64 || $this->pepper === '') {
            throw new RuntimeException('Server cryptographic configuration missing');
        }
        $this->x25519Priv = hex2bin($xHex);
        $this->ed25519Seed = hex2bin($eHex);
        $this->bundleMasterKey = hex2bin($bHex);
    }

    public function __destruct() {
        foreach (['x25519Priv', 'ed25519Seed', 'bundleMasterKey', 'pepper', 'ciSyncSecret'] as $prop) {
            if (isset($this->{$prop}) && is_string($this->{$prop}) && $this->{$prop} !== '') {
                @sodium_memzero($this->{$prop});
            }
        }
    }

    public static function compareSemver(string $a, string $b): int {
        $norm = static function (string $s): array {
            $clean = preg_replace('/^[vV]/', '', trim($s));
            $base = explode('-', explode('+', $clean)[0])[0];
            $parts = array_map(static fn($p) => intval(preg_replace('/\D.*$/', '', $p)), explode('.', $base));
            while (count($parts) < 3) {
                $parts[] = 0;
            }
            return $parts;
        };
        $pa = $norm($a);
        $pb = $norm($b);
        $max = max(count($pa), count($pb));
        for ($i = 0; $i < $max; $i++) {
            $va = $pa[$i] ?? 0;
            $vb = $pb[$i] ?? 0;
            if ($va < $vb) return -1;
            if ($va > $vb) return 1;
        }
        return 0;
    }

    private static function checkRateLimit(string $bucket, int $windowSecs, int $maxHits, int $blockSecs, int $now): bool {
        return withLockedJson(RATE_LIMITS_FILE, [], function (&$map, &$dirty) use ($bucket, $windowSecs, $maxHits, $blockSecs, $now) {
            foreach ($map as $k => $b) {
                if ((($b['window_start'] ?? 0) + $windowSecs) <= $now && ($b['blocked_until'] ?? 0) <= $now) {
                    unset($map[$k]);
                    $dirty = true;
                }
            }
            $entry = $map[$bucket] ?? ['window_start' => $now, 'count' => 0, 'blocked_until' => 0];
            if (($entry['blocked_until'] ?? 0) > $now) {
                return false;
            }
            if (($now - ($entry['window_start'] ?? 0)) >= $windowSecs) {
                $entry['window_start'] = $now;
                $entry['count'] = 1;
            } else {
                $entry['count'] = intval($entry['count']) + 1;
                if ($entry['count'] > $maxHits) {
                    $entry['blocked_until'] = $now + $blockSecs;
                    $map[$bucket] = $entry;
                    $dirty = true;
                    return false;
                }
            }
            $map[$bucket] = $entry;
            $dirty = true;
            return true;
        });
    }

    private static function isRateLimited(string $bucket, int $now): bool {
        $map = readJsonFile(RATE_LIMITS_FILE, []);
        return isset($map[$bucket]) && intval($map[$bucket]['blocked_until'] ?? 0) > $now;
    }

    private static function checkAndRecordNonce(string $nonceHex, int $now): bool {
        return withLockedJson(NONCES_FILE, [], function (&$nonces, &$dirty) use ($nonceHex, $now) {
            foreach ($nonces as $k => $exp) {
                if ($exp < ($now - 600)) {
                    unset($nonces[$k]);
                    $dirty = true;
                }
            }
            if (isset($nonces[$nonceHex])) {
                return false;
            }
            $nonces[$nonceHex] = $now + 600;
            $dirty = true;
            return true;
        });
    }

    private function deriveBundleKeys(array $presetStatuses = []): array {
        $out = [];
        foreach (self::BUNDLED_PRESETS as $fname) {
            $idBytes = substr(hash('sha256', 'BUNDLE|' . $fname, true), 0, 16);
            $idHex = bin2hex($idBytes);
            if (($presetStatuses[$idHex]['status'] ?? 'stable') === 'maintenance') {
                continue;
            }
            $keyBytes = hash_hkdf('sha256', $this->bundleMasterKey, 32, $idBytes, '3105-V4-BUNDLE');
            $out[$idHex] = bin2hex($keyBytes);
        }
        return $out;
    }

    private static function maskKey(string $key): string {
        $len = strlen($key);
        if ($len <= 8) return '****';
        return substr($key, 0, 4) . '****' . substr($key, -4);
    }

    private static function durationSeconds(string $dur): ?int {
        $d = strtolower(trim($dur));
        return match ($d) {
            'permanent', 'lifetime', 'vv', 'forever' => null,
            '1h', '1hour' => 3600,
            '1d', '1day' => 86400,
            '7d', '1w' => 7 * 86400,
            '30d', '1m' => 30 * 86400,
            '90d', '3m' => 90 * 86400,
            '365d', '1y' => 365 * 86400,
            default => 30 * 86400,
        };
    }

    public function handleV3(array $req, string $clientIp): array {
        $now = time();
        $v = intval($req['v'] ?? 0);
        $op = (string)($req['op'] ?? '');
        $pkg = (string)($req['pkg'] ?? '');
        $ver = (string)($req['ver'] ?? '');
        $bld = (string)($req['bld'] ?? '');
        $nonceHex = strtolower(trim((string)($req['nonce'] ?? '')));
        $ts = intval($req['ts'] ?? 0);
        $cPubHex = strtolower(trim((string)($req['c_pub'] ?? '')));
        $fpHex = strtolower(trim((string)($req['fp'] ?? '')));
        $ctB64 = (string)($req['ct'] ?? '');

        if ($v !== 3 || !in_array($op, ['preflight', 'activate', 'heartbeat'], true)) {
            return [400, ['error' => 'Unsupported protocol or operation']];
        }
        if (abs($now - $ts) > self::MAX_CLOCK_SKEW) {
            return [403, ['error' => 'Timestamp outside permitted skew']];
        }
        if (!preg_match('/^[0-9a-f]{48}$/', $nonceHex) || !preg_match('/^[0-9a-f]{64}$/', $cPubHex) || !preg_match('/^[0-9a-f]{64}$/', $fpHex)) {
            return [400, ['error' => 'Malformed cryptographic header fields']];
        }

        if (!self::checkRateLimit("ip:$clientIp", 60, 60, 120, $now) || !self::checkRateLimit("fp:$fpHex", 60, 35, 180, $now)) {
            addLog('RATE_LIMIT', '', $op, $clientIp, $fpHex);
            return [429, ['error' => 'Too many requests']];
        }

        if (!self::checkAndRecordNonce($nonceHex, $now)) {
            addLog('REPLAY_REJECTED', '', $nonceHex, $clientIp, $fpHex);
            return [403, ['error' => 'Replay nonce detected']];
        }

        $nonce24 = hex2bin($nonceHex);
        $cPub = hex2bin($cPubHex);
        $shared = sodium_crypto_scalarmult($this->x25519Priv, $cPub);
        if (hash_equals(str_repeat("\x00", 32), $shared)) {
            return [403, ['error' => 'Weak ECDH key']];
        }

        $reqKey = hash_hkdf('sha256', $shared, 32, '3105-V3-REQ', $this->pepper);
        $reqAad = "V3REQ|{$v}|{$op}|{$pkg}|{$ver}|{$bld}|{$fpHex}|{$nonceHex}|{$ts}";
        $ctRaw = base64_decode($ctB64, true);
        if ($ctRaw === false) {
            return [400, ['error' => 'Malformed base64 ciphertext']];
        }
        $pt = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ctRaw, $reqAad, $nonce24, $reqKey);
        @sodium_memzero($reqKey);
        if ($pt === false) {
            @sodium_memzero($shared);
            addLog('AEAD_FAIL', '', $pkg, $clientIp, $fpHex);
            return [403, ['error' => 'Cryptographic verification failed']];
        }

        $inner = json_decode($pt, true);
        @sodium_memzero($pt);
        if (!is_array($inner) || ($inner['op'] ?? '') !== $op || ($inner['pkg'] ?? '') !== $pkg || ($inner['ver'] ?? '') !== $ver || intval($inner['ts'] ?? 0) !== $ts) {
            @sodium_memzero($shared);
            return [403, ['error' => 'Envelope mismatch']];
        }

        $innerKey = (string)($inner['key'] ?? '');
        $proofHex = strtolower(trim((string)($inner['client_proof'] ?? '')));
        $expectedProof = hash_hmac('sha256', $reqAad . '|' . $innerKey, $this->pepper);
        if (!hash_equals($expectedProof, $proofHex)) {
            @sodium_memzero($shared);
            addLog('PROOF_FAIL', '', $pkg, $clientIp, $fpHex);
            return [403, ['error' => 'Client authentication proof invalid']];
        }

        $sendV3 = function (
            string $status,
            string $code,
            bool $serverOpen,
            bool $forceUpdate,
            array $policy,
            string $message,
            ?string $ephKey = null,
            ?string $sessToken = null,
            array $bundleKeys = [],
            ?array $license = null,
            array $presetStatuses = []
        ) use ($op, $pkg, $ver, $fpHex, $nonceHex, $nonce24, &$shared): array {
            $sTs = time();
            $sNonce24 = random_bytes(24);
            $sNonceHex = bin2hex($sNonce24);
            $resAad = "V3RES|3|{$op}|{$pkg}|{$ver}|{$fpHex}|{$nonceHex}|{$sNonceHex}|{$sTs}|{$code}";
            $payload = [
                'status' => $status,
                'code' => $code,
                'op' => $op,
                'server_open' => $serverOpen,
                'force_update' => $forceUpdate,
                'min_version' => $policy['min_required_version'],
                'latest_version' => $policy['latest_version'],
                'download_url' => $policy['download_url'],
                'message' => $message,
                'req_nonce' => $nonceHex,
                's_nonce' => $sNonceHex,
                's_ts' => $sTs,
                'ephemeral_session_key' => $ephKey,
                'session_token' => $sessToken,
                'bundle_keys' => (object)$bundleKeys,
                'preset_statuses' => (object)$presetStatuses,
                'license' => $license ?? [
                    'valid' => false,
                    'key_masked' => '',
                    'expiry' => '',
                    'expiry_ts' => 0,
                    'remaining_seconds' => 0,
                    'is_permanent' => false,
                    'role' => '',
                    'used_devices' => 0,
                    'max_devices' => 0,
                ],
            ];
            $ptBytes = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $resKey = hash_hkdf('sha256', $shared, 32, '3105-V3-RES|' . $nonce24, $this->pepper);
            @sodium_memzero($shared);
            $resCt = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($ptBytes, $resAad, $sNonce24, $resKey);
            @sodium_memzero($resKey);
            @sodium_memzero($ptBytes);
            $ctHash = hash('sha256', $resCt, true);
            $sigMsg = '3105-V3-SIG|' . $resAad . '|' . $ctHash;
            $kp = sodium_crypto_sign_seed_keypair($this->ed25519Seed);
            $sk = sodium_crypto_sign_secretkey($kp);
            $sig = sodium_crypto_sign_detached($sigMsg, $sk);
            @sodium_memzero($sk);
            @sodium_memzero($kp);

            return [200, [
                'v' => 3,
                'op' => $op,
                'pkg' => $pkg,
                'ver' => $ver,
                'fp' => $fpHex,
                'req_nonce' => $nonceHex,
                's_nonce' => $sNonceHex,
                's_ts' => $sTs,
                'code' => $code,
                'ct' => base64_encode($resCt),
                'sig' => bin2hex($sig),
            ]];
        };

        $settings = getSettings();
        $policy = resolvePackagePolicy($settings, $pkg);
        $presetStatuses = self::resolvePresetPolicies($settings);

        // 1. Kill-Switch
        if (!$policy['server_open']) {
            addLog('SERVER_CLOSED_DENY', self::maskKey($innerKey), $pkg, $clientIp, $fpHex);
            return $sendV3('server_closed', 'SERVER_CLOSED', false, false, $policy, $policy['closed_message']);
        }

        // 1b. Device HWID Ban Check
        $banRec = findActiveBannedDevice($fpHex);
        if ($banRec !== null) {
            $banReason = trim((string)($banRec['reason'] ?? ''));
            $banMsg = $banReason !== ''
                ? "Thiết bị này đã bị khóa vĩnh viễn. Lý do: {$banReason}"
                : 'Thiết bị này đã bị Admin cấm truy cập vĩnh viễn khỏi hệ thống.';
            addLog('DEVICE_BANNED_DENY', self::maskKey($innerKey), $banMsg, $clientIp, $fpHex);
            return $sendV3('device_banned', 'DEVICE_BANNED', true, false, $policy, $banMsg);
        }

        // 2. Client Anti-Tamper & Manifest Hash Check
        if (intval($inner['tamper_flags'] ?? 0) !== 0) {
            addLog('CLIENT_TAMPER_FLAGS', self::maskKey($innerKey), 'flags=' . intval($inner['tamper_flags']), $clientIp, $fpHex);
            return $sendV3('denied', 'TAMPER_DETECTED', true, false, $policy, 'Phát hiện can thiệp môi trường thực thi. Phiên bị khóa.');
        }

        $appHash = strtolower(trim((string)($inner['app_hash'] ?? '')));
        $secHash = strtolower(trim((string)($inner['sec_hash'] ?? '')));
        $manifests = array_values(array_filter(getBuildManifests(), static fn($m) => ($m['package_id'] ?? '') === $pkg));
        $authVer = $ver;

        if (!empty($manifests) || !empty($policy['enforce_binary_hash'])) {
            if (!preg_match('/^[0-9a-f]{64}$/', $appHash) || !preg_match('/^[0-9a-f]{64}$/', $secHash)) {
                addLog('HASH_DENY', self::maskKey($innerKey), 'Invalid hash telemetry', $clientIp, $fpHex);
                return $sendV3('denied', 'TAMPER_DETECTED', true, false, $policy, 'Thiếu hoặc sai chữ ký toàn vẹn ứng dụng.');
            }
            $matched = null;
            $appOnly = null;
            foreach ($manifests as $m) {
                if (strtolower($m['app_hash'] ?? '') === $appHash && strtolower($m['sec_hash'] ?? '') === $secHash) {
                    $matched = $m;
                    break;
                }
                if (strtolower($m['app_hash'] ?? '') === $appHash) {
                    $appOnly = $m;
                }
            }
            if ($matched !== null) {
                if (!empty($matched['revoked']) || empty($matched['active'])) {
                    addLog('HASH_DENY', self::maskKey($innerKey), 'Build revoked', $clientIp, $fpHex);
                    return $sendV3('denied', 'TAMPER_DETECTED', true, false, $policy, 'Phiên bản build này đã bị thu hồi.');
                }
                if (self::compareSemver($ver, (string)$matched['version']) !== 0) {
                    addLog('HASH_DENY', self::maskKey($innerKey), 'Version spoof mismatch', $clientIp, $fpHex);
                    return $sendV3('denied', 'TAMPER_DETECTED', true, false, $policy, 'Phát hiện sửa đổi thông tin phiên bản.');
                }
                $authVer = (string)$matched['version'];
            } elseif ($appOnly !== null) {
                addLog('HASH_DENY', self::maskKey($innerKey), 'Sec dylib hash mismatch', $clientIp, $fpHex);
                return $sendV3('denied', 'TAMPER_DETECTED', true, false, $policy, 'Phát hiện can thiệp module bảo mật.');
            } else {
                addLog('HASH_DENY', self::maskKey($innerKey), 'Unrecognized binary hash', $clientIp, $fpHex);
                return $sendV3('denied', 'TAMPER_DETECTED', true, false, $policy, 'Bản dựng không hợp lệ hoặc đã bị patch.');
            }
        }

        // 3. Force Update check
        $outdated = self::compareSemver($authVer, $policy['min_required_version']) < 0;
        $forceNow = $outdated || (!empty($policy['force_update']) && self::compareSemver($authVer, $policy['latest_version']) < 0);
        if ($forceNow) {
            addLog('FORCE_UPDATE_DENY', self::maskKey($innerKey), "ver={$authVer} min={$policy['min_required_version']}", $clientIp, $fpHex);
            return $sendV3('force_update', 'FORCE_UPDATE', true, true, $policy, $policy['update_message']);
        }

        if ($op === 'preflight') {
            return $sendV3('ok', 'OK', true, false, $policy, 'Máy chủ đang hoạt động. Sẵn sàng xác thực key.', null, null, [], null, $presetStatuses);
        }

        // 4. License Validation & Atomic Device Binding
        $cleanKey = trim($innerKey);
        $keyBucket = 'kf:' . substr(hash('sha256', $cleanKey), 0, 16);
        if (self::isRateLimited("ip_kf:$clientIp", $now) || self::isRateLimited($keyBucket, $now)) {
            @sodium_memzero($shared);
            addLog('KEY_BRUTE_BLOCK', self::maskKey($cleanKey), $pkg, $clientIp, $fpHex);
            return [429, ['error' => 'Too many failed license attempts']];
        }
        if ($cleanKey === '' || strlen($cleanKey) > 128) {
            return $sendV3('denied', 'INVALID_KEY', true, false, $policy, 'Vui lòng nhập mã Key hợp lệ.');
        }

        $outcome = withLockedJson(KEYS_FILE, [], function (&$keysList, &$dirty) use ($cleanKey, $op, $pkg, $fpHex, $clientIp, $now) {
            foreach ($keysList as $idx => &$rec) {
                if (strcasecmp(trim((string)($rec['key'] ?? '')), $cleanKey) !== 0) {
                    continue;
                }
                normalizeKey($rec);
                $status = strtolower((string)($rec['status'] ?? 'active'));
                if (in_array($status, ['banned', 'disabled', 'revoked'], true)) {
                    return ['ok' => false, 'code' => 'KEY_REVOKED', 'msg' => 'Mã Key này đã bị khóa hoặc thu hồi!'];
                }
                $boundPkgs = $rec['bound_packages'] ?? [];
                if (!empty($boundPkgs) && !in_array($pkg, $boundPkgs, true)) {
                    return ['ok' => false, 'code' => 'PACKAGE_DENIED', 'msg' => 'Mã Key không hợp lệ cho gói ứng dụng này.'];
                }

                $durSecs = self::durationSeconds((string)($rec['duration'] ?? '30d'));
                $isPerm = ($durSecs === null);
                $expTs = isset($rec['expiry_ts']) ? intval($rec['expiry_ts']) : 0;
                if ($expTs === 0 && !empty($rec['expiry_date']) && $rec['expiry_date'] !== 'permanent') {
                    $parsed = strtotime((string)$rec['expiry_date']);
                    if ($parsed !== false) $expTs = $parsed;
                }
                if (empty($rec['is_used']) && $expTs === 0 && !$isPerm) {
                    $expTs = $now + $durSecs;
                    $rec['expiry_ts'] = $expTs;
                    $rec['expiry_date'] = date('Y-m-d H:i:s', $expTs);
                } elseif ($expTs > 0) {
                    $rec['expiry_ts'] = $expTs;
                }
                if ($expTs > 0 && $now >= $expTs) {
                    return ['ok' => false, 'code' => 'KEY_EXPIRED', 'msg' => 'Key đã hết hạn lúc ' . ($rec['expiry_date'] ?? '') . '!'];
                }

                $foundDevIdx = null;
                foreach ($rec['devices'] as $dIdx => $dev) {
                    if (strcasecmp((string)($dev['hwid'] ?? ''), $fpHex) === 0) {
                        $foundDevIdx = $dIdx;
                        break;
                    }
                }
                $maxDev = intval($rec['max_devices'] ?? 1);
                $nowStr = date('Y-m-d H:i:s', $now);
                if ($foundDevIdx !== null) {
                    $rec['devices'][$foundDevIdx]['last_seen'] = $nowStr;
                    $rec['devices'][$foundDevIdx]['ip'] = $clientIp;
                } else {
                    if ($op === 'heartbeat') {
                        return ['ok' => false, 'code' => 'DEVICE_MISMATCH', 'msg' => 'Thiết bị đã bị gỡ khỏi Key trên hệ thống.'];
                    }
                    if ($maxDev > 0 && count($rec['devices']) >= $maxDev) {
                        return ['ok' => false, 'code' => 'DEVICE_LIMIT', 'msg' => 'Key đã đạt giới hạn thiết bị (' . count($rec['devices']) . "/{$maxDev})."];
                    }
                    $rec['devices'][] = [
                        'hwid' => $fpHex,
                        'activated_at' => $nowStr,
                        'last_seen' => $nowStr,
                        'ip' => $clientIp,
                    ];
                }
                $rec['used_by'] = implode(', ', array_column($rec['devices'], 'hwid'));
                $rec['used_at'] = $rec['used_at'] ?? $nowStr;
                $rec['is_used'] = true;
                $dirty = true;

                $remSecs = $isPerm ? PHP_INT_MAX : max(0, $expTs - $now);
                return [
                    'ok' => true,
                    'summary' => [
                        'valid' => true,
                        'key_masked' => self::maskKey((string)$rec['key']),
                        'expiry' => $isPerm ? 'Vĩnh viễn' : ($rec['expiry_date'] ?? date('Y-m-d H:i:s', $expTs)),
                        'expiry_ts' => $expTs,
                        'remaining_seconds' => $remSecs,
                        'is_permanent' => $isPerm,
                        'role' => (string)($rec['role'] ?? 'member'),
                        'used_devices' => count($rec['devices']),
                        'max_devices' => $maxDev,
                    ],
                ];
            }
            return ['ok' => false, 'code' => 'INVALID_KEY', 'msg' => 'Mã Key không tồn tại trên hệ thống!'];
        });

        if (empty($outcome['ok'])) {
            self::checkRateLimit($keyBucket, 300, 12, 600, $now);
            self::checkRateLimit("ip_kf:$clientIp", 300, 25, 600, $now);
            addLog($outcome['code'], self::maskKey($cleanKey), $outcome['msg'], $clientIp, $fpHex);
            return $sendV3('denied', $outcome['code'], true, false, $policy, $outcome['msg']);
        }

        $ephKey = bin2hex(random_bytes(32));
        $bundleKeys = $this->deriveBundleKeys($presetStatuses);
        $sessionToken = hash('sha256', "{$ephKey}|{$fpHex}|{$pkg}|{$now}");
        addLog('KEY_ACTIVATED', $outcome['summary']['key_masked'], "ver={$authVer}", $clientIp, $fpHex);

        return $sendV3(
            'ok',
            'OK',
            true,
            false,
            $policy,
            'Xác thực thành công!',
            $ephKey,
            $sessionToken,
            $bundleKeys,
            $outcome['summary'],
            $presetStatuses
        );
    }

    public function handleCiRegisterBuild(array $req): array {
        $now = time();
        $ts = intval($req['ts'] ?? 0);
        if (abs($now - $ts) > self::MAX_CLOCK_SKEW) {
            return [403, ['error' => 'Timestamp expired']];
        }
        $pkg = (string)($req['package_id'] ?? '');
        $ver = (string)($req['version'] ?? '');
        $bld = (string)($req['build'] ?? '');
        $appHash = strtolower(trim((string)($req['app_hash'] ?? '')));
        $secHash = strtolower(trim((string)($req['sec_hash'] ?? '')));
        $nonce = (string)($req['nonce'] ?? '');
        $sig = strtolower(trim((string)($req['sig'] ?? '')));
        $note = (string)($req['note'] ?? '');
        $autoLatest = !empty($req['auto_update_latest']);

        if ($this->ciSyncSecret === '' || !preg_match('/^[0-9a-f]{64}$/', $appHash) || !preg_match('/^[0-9a-f]{64}$/', $secHash)) {
            return [400, ['error' => 'Invalid CI configuration or hashes']];
        }
        $signInput = "CIREG|{$pkg}|{$ver}|{$bld}|{$appHash}|{$secHash}|{$nonce}|{$ts}";
        $expectedSig = hash_hmac('sha256', $signInput, $this->ciSyncSecret);
        if (!hash_equals($expectedSig, $sig)) {
            return [403, ['error' => 'Invalid CI signature']];
        }
        if (!self::checkAndRecordNonce('ci:' . $nonce, $now)) {
            return [403, ['error' => 'Duplicate CI nonce']];
        }

        withLockedJson(MANIFESTS_FILE, [], function (&$list, &$dirty) use ($pkg, $ver, $bld, $appHash, $secHash, $note, $now) {
            $updated = false;
            foreach ($list as &$m) {
                if (($m['package_id'] ?? '') === $pkg && strtolower($m['app_hash'] ?? '') === $appHash && strtolower($m['sec_hash'] ?? '') === $secHash) {
                    $m['version'] = $ver;
                    $m['build'] = $bld;
                    $m['active'] = true;
                    $m['revoked'] = false;
                    $m['registered_at'] = date('Y-m-d H:i:s', $now);
                    $m['note'] = $note;
                    $updated = true;
                    break;
                }
            }
            unset($m);
            if (!$updated) {
                $list[] = [
                    'package_id' => $pkg,
                    'version' => $ver,
                    'build' => $bld,
                    'app_hash' => $appHash,
                    'sec_hash' => $secHash,
                    'active' => true,
                    'revoked' => false,
                    'registered_at' => date('Y-m-d H:i:s', $now),
                    'note' => $note,
                ];
            }
            $dirty = true;
            return true;
        });

        if ($autoLatest) {
            $settings = getSettings();
            $pkgCfg = $settings['packages'][$pkg] ?? [];
            $pkgCfg['latest_version'] = $ver;
            $settings['packages'][$pkg] = $pkgCfg;
            if (self::compareSemver((string)($settings['latest_version'] ?? '0.0.0'), $ver) < 0) {
                $settings['latest_version'] = $ver;
            }
            saveSettings($settings);
        }

        addLog('CI_BUILD_SYNC', 'CI', "pkg={$pkg} ver={$ver} app=" . substr($appHash, 0, 12), 'github-actions', $appHash);
        return [200, ['ok' => true, 'package_id' => $pkg, 'version' => $ver, 'app_hash' => $appHash, 'sec_hash' => $secHash]];
    }
}
