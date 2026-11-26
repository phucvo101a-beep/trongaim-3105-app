<?php
/**
 * Tobi AIM - Admin Control Panel
 * Quản lý 5 loại key bản quyền: 1 giờ, 1 ngày, 7 ngày, 30 ngày, vĩnh viễn
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/CoreEngine.php';

if (PHP_SAPI !== 'cli' && !headers_sent()) {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
}

$settings = getSettings();
$msg = $_SESSION['flash_msg'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
$newlyCreatedKeys = $_SESSION['newly_created_keys'] ?? [];
$newlyCreatedMeta = $_SESSION['newly_created_meta'] ?? null;
unset($_SESSION['flash_msg'], $_SESSION['flash_error'], $_SESSION['newly_created_keys'], $_SESSION['newly_created_meta']);

function csrfField(): string {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(getCsrfToken(), ENT_QUOTES, 'UTF-8') . '">';
}

function checkAdminLoginRateLimit(string $ip, bool $recordFailure = false): bool {
    return withLockedJson(LOGIN_LIMITS_FILE, [], function (&$map, &$dirty) use ($ip, $recordFailure) {
        $now = time();
        foreach ($map as $k => $v) {
            if (($v['blocked_until'] ?? 0) <= $now && ($v['window_start'] ?? 0) + 600 <= $now) {
                unset($map[$k]);
                $dirty = true;
            }
        }
        $entry = $map[$ip] ?? ['window_start' => $now, 'count' => 0, 'blocked_until' => 0];
        if (($entry['blocked_until'] ?? 0) > $now) {
            return false;
        }
        if ($recordFailure) {
            if (($now - ($entry['window_start'] ?? 0)) >= 600) {
                $entry['window_start'] = $now;
                $entry['count'] = 1;
            } else {
                $entry['count'] = intval($entry['count']) + 1;
                if ($entry['count'] >= 6) {
                    $entry['blocked_until'] = $now + 900;
                }
            }
            $map[$ip] = $entry;
            $dirty = true;
        }
        return true;
    });
}

$clientDevInfo = resolveClientDeviceIdentity(isset($_POST['device_fp']) ? (string)$_POST['device_fp'] : null, true);

// Đăng xuất
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    logoutAdminSession(
        (string)($_SESSION['admin_current_user'] ?? ''),
        !empty($_SESSION['admin_is_master']),
        (string)($_SESSION['admin_session_token'] ?? '')
    );
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    @session_destroy();
    header('Location: admin.php');
    exit;
}

// Đăng nhập Admin (CSRF + Rate-limit + Argon2/Bcrypt Hash + 1 Tài khoản = 1 Thiết bị HWID)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'admin_login') {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $adminUser = trim($_POST['username'] ?? '');
    $adminPass = trim($_POST['password'] ?? '');

    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Phiên bảo mật CSRF không hợp lệ. Vui lòng tải lại trang!';
    } elseif (!checkAdminLoginRateLimit($clientIp, false)) {
        $error = 'Quá nhiều lần đăng nhập sai. Vui lòng thử lại sau 15 phút!';
    } else {
        $authRes = authenticateAndBindAdminAccount($adminUser, $adminPass, $settings, $clientDevInfo, $clientIp);
        if (!empty($authRes['ok'])) {
            @session_regenerate_id(true);
            $_SESSION['admin_logged_in'] = true;
            $_SESSION['admin_current_user'] = $authRes['username'];
            $_SESSION['admin_is_master'] = !empty($authRes['is_master']);
            $_SESSION['admin_session_token'] = $authRes['session_token'];
            $_SESSION['admin_device_hwid'] = $authRes['hwid'];
            $_SESSION['admin_device_fp_hash'] = $authRes['fp_hash'];
            $_SESSION['admin_ua_hash'] = $authRes['ua_hash'];
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $bindNote = !empty($authRes['bound_now'])
                ? " (Gắn thiết bị đầu tiên HWID: {$authRes['hwid']} • {$authRes['device_label']})"
                : " (HWID: {$authRes['hwid']})";
            addLog('login_success', $authRes['username'], 'Đăng nhập trang quản trị Server Key thành công' . $bindNote, $clientIp, $authRes['hwid']);
            header('Location: admin.php');
            exit;
        }
        checkAdminLoginRateLimit($clientIp, true);
        $failCode = (string)($authRes['code'] ?? '');
        $logType = in_array($failCode, ['HWID_MISMATCH', 'DEVICE_BANNED', 'HWID_BLOCKED'], true) ? 'ACCOUNT_HWID_DENY' : 'login_fail';
        addLog($logType, $adminUser, (string)($authRes['error'] ?? 'Đăng nhập admin thất bại'), $clientIp, $clientDevInfo['hwid']);
        $error = $authRes['error'] ?: 'Sai tài khoản hoặc mật khẩu quản trị!';
    }
}

$isLoggedIn = !empty($_SESSION['admin_logged_in']);
if ($isLoggedIn) {
    $sessCheck = verifyCurrentAdminSession($settings, $clientDevInfo);
    if (empty($sessCheck['valid'])) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        @session_destroy();
        $isLoggedIn = false;
        if (!empty($sessCheck['reason'])) {
            $error = $sessCheck['reason'];
        }
    }
}

// Xử lý các thao tác quản trị khi đã đăng nhập (Bắt buộc CSRF Token)
if ($isLoggedIn && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $act = $_POST['action'];
    $actor = $_SESSION['admin_current_user'] ?? 'admin';
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $_SESSION['flash_error'] = 'Lỗi xác thực CSRF Token! Vui lòng thao tác lại.';
        header('Location: admin.php');
        exit;
    }

    // 1. Thêm tài khoản thủ công (5 loại thời hạn: 1h, 1d, 7d, 30d, permanent)
    if ($act === 'add_user') {
        $uName = strtolower(trim($_POST['username'] ?? ''));
        $uPass = trim($_POST['password'] ?? '');
        $uRole = trim($_POST['role'] ?? 'member');
        $uHwid = trim($_POST['hwid'] ?? '');
        $uDuration = trim($_POST['duration'] ?? '30d');

        if (empty($uName) || empty($uPass)) {
            $error = 'Vui lòng nhập đầy đủ tên tài khoản và mật khẩu!';
        } elseif (findUserByUsername($uName)) {
            $error = 'Tài khoản "' . htmlspecialchars($uName) . '" đã tồn tại!';
        } else {
            $expiry = calculateExpiryDate($uDuration);

            upsertUser([
                'id' => time() . random_int(100, 999),
                'username' => $uName,
                'password' => hashUserPassword($uPass),
                'role' => $uRole,
                'hwid' => $uHwid,
                'device_fp_hash' => '',
                'device_label' => '',
                'active_session_token' => '',
                'active_ua_hash' => '',
                'is_active' => true,
                'expiry_date' => $expiry,
                'created_at' => date('Y-m-d H:i:s'),
                'api_key' => '',
                'last_login' => null,
                'last_ip' => '',
                'is_hwid_blocked' => false
            ]);
            $durLabel = formatDurationLabel($uDuration);
            addLog('admin', $actor, "Thêm tài khoản mới: {$uName} ({$uRole}, Hạn: {$durLabel})");
            $msg = "Đã thêm thành công tài khoản: {$uName} (Hạn: {$durLabel})";
        }
    }

    // 2. Xóa tài khoản
    elseif ($act === 'delete_user') {
        $uName = strtolower(trim($_POST['username'] ?? ''));
        withLockedJson(USERS_FILE, [], function (&$users, &$dirty) use ($uName) {
            $newUsers = [];
            foreach ($users as $u) {
                if (strtolower(trim((string)($u['username'] ?? ''))) !== $uName) {
                    $newUsers[] = $u;
                } else {
                    $dirty = true;
                }
            }
            $users = $newUsers;
            return true;
        });
        addLog('admin', $actor, "Đã xóa tài khoản: {$uName}");
        $msg = "Đã xóa tài khoản: {$uName}";
    }

    // 3. Khóa / Mở khóa tài khoản
    elseif ($act === 'toggle_status') {
        $uName = strtolower(trim($_POST['username'] ?? ''));
        $toggled = withLockedJson(USERS_FILE, [], function (&$users, &$dirty) use ($uName) {
            foreach ($users as $i => $u) {
                if (strtolower(trim((string)($u['username'] ?? ''))) === $uName) {
                    $users[$i]['is_active'] = empty($u['is_active']);
                    if (empty($users[$i]['is_active'])) {
                        $users[$i]['active_session_token'] = '';
                    }
                    $dirty = true;
                    return $users[$i]['is_active'] ? 'Kích hoạt' : 'Khóa';
                }
            }
            return null;
        });
        if ($toggled !== null) {
            addLog('admin', $actor, "Thay đổi trạng thái tài khoản {$uName}: {$toggled}");
            $msg = "Đã {$toggled} tài khoản: {$uName}";
        }
    }

    // 4. Đặt lại HWID (mở slot liên kết 1 thiết bị mới & đăng xuất thiết bị cũ ngay lập tức)
    elseif ($act === 'reset_hwid') {
        $uName = strtolower(trim($_POST['username'] ?? ''));
        $found = withLockedJson(USERS_FILE, [], function (&$users, &$dirty) use ($uName) {
            foreach ($users as $i => $u) {
                if (strtolower(trim((string)($u['username'] ?? ''))) === $uName) {
                    $users[$i]['hwid'] = '';
                    $users[$i]['device_fp_hash'] = '';
                    $users[$i]['device_label'] = '';
                    $users[$i]['active_session_token'] = '';
                    $users[$i]['active_ua_hash'] = '';
                    $dirty = true;
                    return true;
                }
            }
            return false;
        });
        if ($found) {
            addLog('admin', $actor, "Reset HWID tài khoản: {$uName}");
            $msg = "Đã reset HWID & thu hồi phiên của tài khoản: {$uName}. Thiết bị mới sẽ tự động liên kết ở lần đăng nhập tiếp theo.";
        }
    }

    // 4b. Đuổi phiên đăng nhập (Kick session nhưng vẫn giữ HWID máy đã gắn)
    elseif ($act === 'kick_user_session') {
        $uName = strtolower(trim($_POST['username'] ?? ''));
        $kicked = withLockedJson(USERS_FILE, [], function (&$users, &$dirty) use ($uName) {
            foreach ($users as $i => $u) {
                if (strtolower(trim((string)($u['username'] ?? ''))) === $uName) {
                    $users[$i]['active_session_token'] = '';
                    $dirty = true;
                    return true;
                }
            }
            return false;
        });
        if ($kicked) {
            addLog('admin', $actor, "Kick phiên đăng nhập tài khoản: {$uName}");
            $msg = "Đã đăng xuất bắt buộc tài khoản {$uName} (vẫn giữ liên kết HWID thiết bị hiện tại).";
        }
    }

    // 5. Gia hạn thời gian sử dụng
    elseif ($act === 'extend_user') {
        $uName = strtolower(trim($_POST['username'] ?? ''));
        $addDuration = trim($_POST['add_duration'] ?? '30d');
        $updated = withLockedJson(USERS_FILE, [], function (&$users, &$dirty) use ($uName, $addDuration) {
            foreach ($users as $i => $u) {
                if (strtolower(trim((string)($u['username'] ?? ''))) === $uName) {
                    $currentExp = $users[$i]['expiry_date'] ?? 'permanent';
                    $users[$i]['expiry_date'] = calculateExpiryDate($addDuration, $currentExp);
                    $dirty = true;
                    return true;
                }
            }
            return false;
        });
        if ($updated) {
            $label = formatDurationLabel($addDuration);
            addLog('admin', $actor, "Gia hạn tài khoản {$uName}: {$label}");
            $msg = "Đã gia hạn tài khoản {$uName}: {$label}";
        }
    }

    // 6. Tạo 5 loại mã Key bản quyền: 1h, 1d, 7d, 30d, permanent
    elseif ($act === 'create_key') {
        $duration = trim($_POST['key_duration'] ?? '30d');
        $role = trim($_POST['key_role'] ?? 'vip');
        $qty = max(1, min(50, intval($_POST['quantity'] ?? 1)));
        $maxDevices = isset($_POST['max_devices']) ? intval($_POST['max_devices']) : 1;

        // Định dạng prefix theo thời hạn
        $prefix = 'VIP-';
        if ($duration === '1h') $prefix = '1H-';
        elseif ($duration === '1d') $prefix = '1D-';
        elseif ($duration === '7d') $prefix = '7D-';
        elseif ($duration === '30d') $prefix = '30D-';
        elseif ($duration === 'permanent') $prefix = 'LIFE-';

        $keys = getKeys();
        $createdKeys = [];
        for ($k = 0; $k < $qty; $k++) {
            $keyCode = 'TOBIAIM-' . $prefix . strtoupper(substr(bin2hex(random_bytes(3)), 0, 4) . '-' . substr(bin2hex(random_bytes(3)), 0, 4));
            $keys[] = [
                'key' => $keyCode,
                'duration' => $duration, // 1h, 1d, 7d, 30d, permanent
                'role' => $role,
                'status' => 'active',
                'max_devices' => $maxDevices,
                'devices' => [],
                'expiry_date' => null,
                'expiry_ts' => 0,
                'is_used' => false,
                'used_by' => null,
                'used_at' => null,
                'created_at' => date('Y-m-d H:i:s')
            ];
            $createdKeys[] = $keyCode;
        }
        saveKeys($keys);
        $durName = formatDurationLabel($duration);
        $devName = ($maxDevices === 0) ? 'Không giới hạn thiết bị' : "{$maxDevices} thiết bị";
        addLog('admin', $actor, "Tạo {$qty} Key bản quyền mới loại {$durName} (Giới hạn: {$devName})");
        $msg = "Đã tạo thành công {$qty} Key bản quyền loại {$durName} (Giới hạn: {$devName})!";
        $_SESSION['newly_created_keys'] = $createdKeys;
        $_SESSION['newly_created_meta'] = [
            'duration' => $durName,
            'devices' => $devName,
            'qty' => $qty,
            'role' => strtoupper($role)
        ];
    }

    // 7. Xóa Key bản quyền
    elseif ($act === 'delete_key') {
        $keyCode = strtoupper(trim($_POST['key'] ?? ''));
        $keys = getKeys();
        $newKeys = [];
        foreach ($keys as $k) {
            if (strtoupper($k['key']) !== $keyCode) {
                $newKeys[] = $k;
            }
        }
        saveKeys($newKeys);
        $msg = "Đã xóa Key: {$keyCode}";
    }

    // 7a. Khóa / Mở khóa Key
    elseif ($act === 'toggle_key_status') {
        $keyCode = strtoupper(trim($_POST['key'] ?? ''));
        $keys = getKeys();
        foreach ($keys as &$k) {
            if (strtoupper($k['key']) === $keyCode) {
                $cur = strtolower((string)($k['status'] ?? 'active'));
                $next = ($cur === 'revoked' || $cur === 'banned') ? 'active' : 'revoked';
                $k['status'] = $next;
                addLog('admin', $actor, "Đổi trạng thái Key {$keyCode} -> {$next}");
                $msg = "Đã chuyển trạng thái Key {$keyCode} sang: " . ($next === 'active' ? 'HOẠT ĐỘNG' : 'ĐÃ KHÓA');
                break;
            }
        }
        unset($k);
        saveKeys($keys);
    }

    // 7b. Reset toàn bộ Key (xóa thiết bị, làm mới thời hạn, cho phép đổi máy)
    elseif ($act === 'reset_key' || $act === 'reset_key_hwid') {
        $keyCode = strtoupper(trim($_POST['key'] ?? ''));
        $keys = getKeys();
        foreach ($keys as &$k) {
            if (strtoupper($k['key']) === $keyCode) {
                $k['devices'] = [];
                $k['used_by'] = null;
                $k['is_used'] = false;
                $k['used_at'] = null;
                $k['activated_at'] = null;
                $k['expiry_date'] = null;
                $k['expiry_ts'] = 0;
                $k['expires_at'] = null;
                $k['status'] = 'active';
                $k['is_banned'] = false;
                addLog('admin', $actor, "Reset toàn bộ Key {$keyCode} về trạng thái ban đầu");
                $msg = "Đã Reset thành công Key: {$keyCode}! Key đã trở về trạng thái mới (chưa sử dụng, xóa toàn bộ thiết bị).";
                break;
            }
        }
        unset($k);
        saveKeys($keys);
    }

    // 7b2. Reset toàn bộ thiết bị của TẤT CẢ các Key
    elseif ($act === 'reset_all_keys') {
        $keys = getKeys();
        $count = 0;
        foreach ($keys as &$k) {
            if (!empty($k['devices']) || !empty($k['is_used'])) {
                $k['devices'] = [];
                $k['used_by'] = null;
                $k['is_used'] = false;
                $count++;
            }
        }
        unset($k);
        saveKeys($keys);
        addLog('admin', 'admin', "Reset toàn bộ thiết bị của {$count} key");
        $msg = "Đã Reset thiết bị cho toàn bộ {$count} Key thành công! Khách hàng có thể đổi máy tự do.";
    }

    // 7c. Xóa 1 thiết bị cụ thể khỏi Key (Kick thiết bị để nhường chỗ)
    elseif ($act === 'remove_key_device') {
        $keyCode = strtoupper(trim($_POST['key'] ?? ''));
        $hwidToRemove = trim($_POST['hwid'] ?? '');
        $keys = getKeys();
        foreach ($keys as &$k) {
            if (strtoupper($k['key']) === $keyCode) {
                $newDevs = [];
                $devList = $k['devices'] ?? [];
                foreach ($devList as $dev) {
                    if (strcasecmp(trim($dev['hwid']), $hwidToRemove) !== 0) {
                        $newDevs[] = $dev;
                    }
                }
                $k['devices'] = $newDevs;
                $k['used_by'] = !empty($newDevs) ? implode(', ', array_column($newDevs, 'hwid')) : null;
                if (empty($newDevs)) {
                    $k['is_used'] = false;
                }
                addLog('admin', 'admin', "Đã gỡ thiết bị {$hwidToRemove} khỏi Key {$keyCode}");
                $msg = "Đã gỡ thiết bị ({$hwidToRemove}) khỏi Key: {$keyCode} thành công!";
                break;
            }
        }
        unset($k);
        saveKeys($keys);
    }

    // 7d. Cập nhật số thiết bị tối đa cho Key đã có
    elseif ($act === 'update_key_max_devices') {
        $keyCode = strtoupper(trim($_POST['key'] ?? ''));
        $newMax = max(0, intval($_POST['max_devices'] ?? 1));
        $keys = getKeys();
        foreach ($keys as &$k) {
            if (strtoupper($k['key']) === $keyCode) {
                $k['max_devices'] = $newMax;
                $devName = ($newMax === 0) ? 'Không giới hạn thiết bị' : "{$newMax} thiết bị";
                addLog('admin', 'admin', "Cập nhật giới hạn thiết bị Key {$keyCode} -> {$devName}");
                $msg = "Đã cập nhật giới hạn thiết bị cho Key {$keyCode} thành: {$devName}!";
                break;
            }
        }
        unset($k);
        saveKeys($keys);
    }

    // 8. Cập nhật Cài đặt hệ thống
    elseif ($act === 'update_settings') {
        $settings['app_name'] = trim($_POST['app_name'] ?? 'Tobi AIM');
        $settings['admin_user'] = trim($_POST['admin_user'] ?? 'tobiaim_admin');
        if (!empty($_POST['admin_pass'])) {
            $settings['admin_pass_hash'] = hashUserPassword(trim($_POST['admin_pass']));
        }
        $settings['allow_register'] = !empty($_POST['allow_register']);
        $settings['require_key'] = !empty($_POST['require_key']);
        $settings['auto_activate'] = !empty($_POST['auto_activate']);
        $settings['default_duration'] = trim($_POST['default_duration'] ?? '30d');
        $settings['bind_hwid'] = !empty($_POST['bind_hwid']);
        $settings['lock_master_hwid'] = !empty($_POST['lock_master_hwid']);
        $settings['telegram_support'] = trim($_POST['telegram_support'] ?? '');

        saveSettings($settings);
        addLog('admin', $actor, "Cập nhật cấu hình hệ thống");
        $msg = "Đã lưu cài đặt hệ thống thành công!";
    }

    elseif ($act === 'reset_master_hwid') {
        withLockedJson(MASTER_SESSION_FILE, [], function (&$master, &$dirty) {
            $master['hwid'] = '';
            $master['device_fp_hash'] = '';
            $master['device_label'] = '';
            $dirty = true;
            return true;
        });
        addLog('admin', $actor, "Reset liên kết HWID cho tài khoản Master Admin");
        $msg = "Đã xóa liên kết HWID của Master Admin. Máy tiếp theo đăng nhập sẽ trở thành thiết bị chính thức.";
    }

    // 9. Công tắc Đóng/Mở Server & Ép Cập Nhật (Toàn hệ thống)
    elseif ($act === 'update_security_policy') {
        $isOpen = !empty($_POST['server_open']);
        $settings['server_open'] = $isOpen;
        $settings['system_paused'] = !$isOpen;
        $settings['server_closed_message'] = trim($_POST['server_closed_message'] ?? '');
        $settings['force_update'] = !empty($_POST['force_update']);
        $settings['min_required_version'] = trim($_POST['min_required_version'] ?? '2.1.0');
        $settings['latest_version'] = trim($_POST['latest_version'] ?? '2.1.0');
        $settings['download_url'] = trim($_POST['download_url'] ?? '');
        $settings['update_message'] = trim($_POST['update_message'] ?? '');
        $settings['enforce_binary_hash'] = !empty($_POST['enforce_binary_hash']);
        saveSettings($settings);
        addLog('SECURITY_POLICY', $actor, 'Cập nhật Kill-Switch (' . ($isOpen ? 'OPEN' : 'CLOSED') . '), min_ver=' . $settings['min_required_version']);
        $msg = $isOpen ? 'Đã MỞ Server & lưu chính sách cập nhật thành công!' : 'CẢNH BÁO: Đã ĐÓNG Server toàn hệ thống! App sẽ khóa mọi truy cập ngay lập tức.';
    }

    // 10. Cấu hình Kill-Switch / Force Update theo từng Gói App (Bundle ID)
    elseif ($act === 'upsert_package_policy') {
        $pkgId = trim($_POST['package_id'] ?? '');
        if ($pkgId !== '') {
            if (!isset($settings['packages']) || !is_array($settings['packages'])) {
                $settings['packages'] = [];
            }
            $settings['packages'][$pkgId] = [
                'server_open' => !empty($_POST['pkg_server_open']),
                'server_closed_message' => trim($_POST['pkg_closed_message'] ?? ''),
                'force_update' => !empty($_POST['pkg_force_update']),
                'min_required_version' => trim($_POST['pkg_min_version'] ?? ''),
                'latest_version' => trim($_POST['pkg_latest_version'] ?? ''),
                'download_url' => trim($_POST['pkg_download_url'] ?? ''),
                'update_message' => trim($_POST['pkg_update_message'] ?? ''),
                'enforce_binary_hash' => !empty($_POST['pkg_enforce_hash']),
            ];
            saveSettings($settings);
            addLog('PKG_POLICY', $actor, "Cập nhật chính sách gói {$pkgId}");
            $msg = "Đã cập nhật chính sách cho gói {$pkgId}!";
        }
    }

    elseif ($act === 'delete_package_policy') {
        $pkgId = trim($_POST['package_id'] ?? '');
        if (isset($settings['packages'][$pkgId])) {
            unset($settings['packages'][$pkgId]);
            saveSettings($settings);
            $msg = "Đã xóa cấu hình riêng của gói {$pkgId}.";
        }
    }

    // 10b. Quản lý trạng thái Đang ổn định / Bảo trì cho từng file mod preset (.3105)
    elseif ($act === 'save_preset_policies') {
        $statusesIn = is_array($_POST['preset_status'] ?? null) ? $_POST['preset_status'] : [];
        $messagesIn = is_array($_POST['preset_message'] ?? null) ? $_POST['preset_message'] : [];
        $newPolicies = [];
        $maintCount = 0;
        foreach (CoreEngine::BUNDLED_PRESETS as $fname) {
            $rawSt = strtolower(trim((string)($statusesIn[$fname] ?? 'stable')));
            $st = ($rawSt === 'maintenance') ? 'maintenance' : 'stable';
            if ($st === 'maintenance') {
                $maintCount++;
            }
            $newPolicies[$fname] = [
                'status' => $st,
                'message' => trim((string)($messagesIn[$fname] ?? '')),
            ];
        }
        $settings['preset_policies'] = $newPolicies;
        saveSettings($settings);
        addLog('PRESET_POLICY', $actor, 'Cập nhật trạng thái ' . count($newPolicies) . " file mod (Bảo trì: {$maintCount})");
        $msg = $maintCount > 0
            ? "Đã lưu trạng thái file mod ({$maintCount} file đang Bảo trì)."
            : 'Đã lưu trạng thái: tất cả file mod đều Đang ổn định.';
    }

    // 11. Quản lý Build Hash Manifests (Anti-Patch / Anti-Re-Sign)
    elseif ($act === 'add_build_manifest') {
        $pkgId = trim($_POST['package_id'] ?? '');
        $ver = trim($_POST['version'] ?? '');
        $bld = trim($_POST['build'] ?? '');
        $appHash = strtolower(trim($_POST['app_hash'] ?? ''));
        $secHash = strtolower(trim($_POST['sec_hash'] ?? ''));
        $note = trim($_POST['note'] ?? 'Manual entry');
        if ($pkgId === '' || $ver === '' || !preg_match('/^[0-9a-f]{64}$/', $appHash) || !preg_match('/^[0-9a-f]{64}$/', $secHash)) {
            $error = 'Vui lòng nhập đúng Package ID, Version và đủ 64 ký tự hex SHA-256 cho App & Dylib.';
        } else {
            $manifests = getBuildManifests();
            $manifests[] = [
                'package_id' => $pkgId,
                'version' => $ver,
                'build' => $bld,
                'app_hash' => $appHash,
                'sec_hash' => $secHash,
                'active' => true,
                'revoked' => false,
                'registered_at' => date('Y-m-d H:i:s'),
                'note' => $note,
            ];
            saveBuildManifests($manifests);
            addLog('MANIFEST_ADD', $actor, "Thêm Build Hash {$pkgId} v{$ver}");
            $msg = "Đã đăng ký Build Hash hợp lệ cho {$pkgId} v{$ver}.";
        }
    }

    elseif ($act === 'toggle_manifest_revoke') {
        $idx = intval($_POST['manifest_idx'] ?? -1);
        $manifests = getBuildManifests();
        if (isset($manifests[$idx])) {
            $rev = !empty($manifests[$idx]['revoked']);
            $manifests[$idx]['revoked'] = !$rev;
            $manifests[$idx]['active'] = $rev;
            saveBuildManifests($manifests);
            addLog('MANIFEST_TOGGLE', $actor, ($rev ? 'Khôi phục' : 'Thu hồi') . ' build ' . ($manifests[$idx]['version'] ?? ''));
            $msg = $rev ? 'Đã khôi phục bản build.' : 'Đã thu hồi bản build!';
        }
    }

    elseif ($act === 'delete_manifest') {
        $idx = intval($_POST['manifest_idx'] ?? -1);
        $manifests = getBuildManifests();
        if (isset($manifests[$idx])) {
            array_splice($manifests, $idx, 1);
            saveBuildManifests($manifests);
            $msg = 'Đã xóa bản ghi Build Hash.';
        }
    }

    // 12. Ban / Gỡ Ban thiết bị vĩnh viễn theo HWID máy
    elseif ($act === 'ban_device') {
        $hwidToBan = trim((string)($_POST['hwid'] ?? ''));
        $reason = trim((string)($_POST['reason'] ?? 'Vi phạm điều khoản sử dụng / Can thiệp hệ thống'));
        $sourceKey = trim((string)($_POST['source_key'] ?? ''));
        if ($hwidToBan === '') {
            $error = 'Vui lòng nhập mã HWID thiết bị cần Ban!';
        } else {
            banDeviceHwid($hwidToBan, $reason, $actor, $sourceKey);
            addLog('BAN_HWID', $actor, "Đã BAN thiết bị HWID {$hwidToBan} (Lý do: {$reason})", null, $hwidToBan);
            $msg = "Đã BAN vĩnh viễn thiết bị HWID: {$hwidToBan}!";
        }
    }

    elseif ($act === 'unban_device') {
        $hwidToUnban = trim((string)($_POST['hwid'] ?? ''));
        if ($hwidToUnban !== '' && unbanDeviceHwid($hwidToUnban)) {
            addLog('UNBAN_HWID', $actor, "Đã gỡ Ban thiết bị HWID {$hwidToUnban}", null, $hwidToUnban);
            $msg = "Đã gỡ Ban cho thiết bị HWID: {$hwidToUnban}!";
        }
    }

    // PRG Pattern (Post/Redirect/Get): Chuyển hướng trình duyệt sang GET để F5 không bao giờ bị tạo key lặp lại
    if (!empty($msg)) {
        $_SESSION['flash_msg'] = $msg;
    }
    if (!empty($error)) {
        $_SESSION['flash_error'] = $error;
    }

    $tabParam = 'keysTab';
    $returnTab = trim((string)($_POST['return_tab'] ?? ''));
    if (in_array($returnTab, ['keysTab', 'securityTab', 'usersTab', 'settingsTab', 'logsTab'], true)) {
        $tabParam = $returnTab;
    } elseif (in_array($act, ['add_user', 'delete_user', 'toggle_status', 'reset_hwid', 'kick_user_session', 'extend_user'])) {
        $tabParam = 'usersTab';
    } elseif (in_array($act, ['update_settings', 'reset_master_hwid'])) {
        $tabParam = 'settingsTab';
    } elseif (in_array($act, ['update_security_policy', 'upsert_package_policy', 'delete_package_policy', 'save_preset_policies', 'add_build_manifest', 'toggle_manifest_revoke', 'delete_manifest', 'ban_device', 'unban_device'])) {
        $tabParam = 'securityTab';
    }

    header('Location: admin.php?tab=' . $tabParam);
    exit;
}

$allUsers = getUsers();
$allKeys = getKeys();
$allLogs = readJsonFile(LOGS_FILE, []);
$allManifests = getBuildManifests();
$presetPoliciesView = CoreEngine::resolvePresetPolicies($settings);
$allBannedDevices = getBannedDevices();
$bannedHwidMap = [];
foreach ($allBannedDevices as $bd) {
    if (!empty($bd['active']) && !empty($bd['hwid'])) {
        $bannedHwidMap[strtolower(trim((string)$bd['hwid']))] = $bd;
    }
}
$isServerOpenGlobal = !empty($settings['server_open']) && empty($settings['system_paused']);

$search = strtolower(trim($_GET['q'] ?? ''));
$keySearch = strtolower(trim($_GET['key_q'] ?? ''));
if (!empty($search)) {
    $filteredUsers = [];
    foreach ($allUsers as $u) {
        if (strpos(strtolower($u['username']), $search) !== false || strpos(strtolower($u['hwid'] ?? ''), $search) !== false) {
            $filteredUsers[] = $u;
        }
    }
} else {
    $filteredUsers = $allUsers;
}

$totalUsers = count($allUsers);
$activeUsers = count(array_filter($allUsers, function($u) { return !empty($u['is_active']); }));
$totalKeys = count($allKeys);
$unusedKeys = count(array_filter($allKeys, function($k) { return empty($k['is_used']); }));
$totalConnectedDevices = 0;
foreach ($allKeys as $k) {
    if (!empty($k['devices']) && is_array($k['devices'])) {
        $totalConnectedDevices += count($k['devices']);
    }
}
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quản Trị Hệ Thống - <?= htmlspecialchars($settings['app_name']) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        :root {
            --bg-base: #0a0b10;
            --bg-surface: #12141c;
            --bg-card: #181b26;
            --bg-input: #0e1017;
            --border-color: rgba(147, 51, 234, 0.2);
            --border-focus: #a855f7;
            --primary: #9333ea;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --radius-md: 10px;
            --radius-lg: 16px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { background: var(--bg-base); color: var(--text-main); min-height: 100vh; font-size: 14px; }
        .login-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .login-box { width: 100%; max-width: 400px; background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 32px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
        .admin-nav { background: var(--bg-surface); border-bottom: 1px solid var(--border-color); padding: 14px 24px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; }
        .nav-brand { font-size: 18px; font-weight: 800; display: flex; align-items: center; gap: 10px; color: #fff; }
        .nav-links { display: flex; gap: 12px; align-items: center; }
        .nav-btn { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); color: #cbd5e1; padding: 7px 14px; border-radius: var(--radius-md); text-decoration: none; font-size: 13px; font-weight: 600; transition: all 0.2s; }
        .nav-btn:hover { background: rgba(255,255,255,0.12); color: #fff; }
        .nav-btn.logout { color: #fca5a5; border-color: rgba(239,68,68,0.3); }
        .container { max-width: 1240px; margin: 0 auto; padding: 24px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 18px 20px; display: flex; align-items: center; justify-content: space-between; }
        .stat-val { font-size: 26px; font-weight: 800; color: #fff; margin-top: 4px; }
        .stat-lbl { font-size: 12.5px; color: var(--text-muted); font-weight: 500; }
        .stat-icon { width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
        .icon-purple { background: rgba(147, 51, 234, 0.15); color: #c084fc; }
        .icon-green { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .icon-cyan { background: rgba(6, 182, 212, 0.15); color: #22d3ee; }
        .tabs { display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 12px; overflow-x: auto; }
        .tab-btn { background: none; border: none; color: var(--text-muted); font-size: 14px; font-weight: 600; padding: 8px 16px; border-radius: var(--radius-md); cursor: pointer; transition: all 0.2s; white-space: nowrap; }
        .tab-btn.active { background: var(--primary); color: #fff; }
        .content-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 22px; margin-bottom: 24px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; flex-wrap: wrap; gap: 12px; }
        .card-title { font-size: 16px; font-weight: 700; color: #f1f5f9; display: flex; align-items: center; gap: 8px; }
        .table-responsive { width: 100%; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: rgba(255,255,255,0.03); color: var(--text-muted); font-weight: 600; font-size: 12.5px; padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,0.08); }
        td { padding: 13px 14px; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 13px; color: #cbd5e1; vertical-align: middle; }
        tr:hover td { background: rgba(255,255,255,0.02); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; }
        .badge-active { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .badge-blocked { background: rgba(239, 68, 68, 0.15); color: #f87171; }
        .badge-vip { background: rgba(147, 51, 234, 0.2); color: #c084fc; }
        .badge-member { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; }
        .form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 16px; }
        .form-group { margin-bottom: 14px; }
        .form-label { display: block; font-size: 12.5px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }
        .form-input, .form-select { width: 100%; background: var(--bg-input); border: 1px solid rgba(255,255,255,0.1); border-radius: var(--radius-md); padding: 10px 14px; color: #fff; font-size: 13.5px; outline: none; }
        .form-input:focus, .form-select:focus { border-color: var(--border-focus); }
        .btn { padding: 8px 14px; border-radius: var(--radius-md); font-size: 12.5px; font-weight: 600; cursor: pointer; border: none; display: inline-flex; align-items: center; gap: 6px; transition: all 0.2s; text-decoration: none; }
        .btn-primary { background: var(--primary); color: #fff; }
        .btn-primary:hover { background: #a855f7; }
        .btn-danger { background: rgba(239,68,68,0.2); color: #f87171; }
        .btn-danger:hover { background: #ef4444; color: #fff; }
        .btn-sm { padding: 5px 10px; font-size: 11.5px; }
        .alert { padding: 12px 16px; border-radius: var(--radius-md); margin-bottom: 20px; font-size: 13.5px; }
        .alert-success { background: rgba(16,185,129,0.15); border: 1px solid #10b981; color: #6ee7b7; }
        .alert-error { background: rgba(239,68,68,0.15); border: 1px solid #ef4444; color: #fca5a5; }
        .code-box { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: var(--bg-input); padding: 5px 10px; border-radius: 6px; font-size: 12px; color: #22d3ee; white-space: nowrap; display: inline-block; user-select: all; letter-spacing: 0.5px; border: 1px solid rgba(34, 211, 238, 0.2); }
    </style>
</head>
<body>

<?php if (!$isLoggedIn): ?>
    <div class="login-wrap">
        <div class="login-box" style="text-align: center;">
            <div style="margin-bottom: 16px;">
                <img src="assets/logo.png" alt="Tobi AIM" style="width: 72px; height: 72px; border-radius: 50%; box-shadow: 0 0 25px rgba(168, 85, 247, 0.45); border: 2px solid rgba(168, 85, 247, 0.5);">
            </div>
            <h2 style="font-size: 22px; font-weight: 800; margin-bottom: 4px; color: #fff; letter-spacing: 0.5px;">Tobi AIM</h2>
            <p style="font-size: 11px; font-weight: 700; color: #22d3ee; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 22px;">Cổng Quản Trị Server Key iOS</p>

            <?php if (!empty($error)): ?>
                <div class="alert alert-error" style="text-align: left;"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <form method="POST" id="adminLoginForm" style="text-align: left;">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="admin_login">
                <input type="hidden" name="device_fp" id="adminDeviceFp" value="">
                <div class="form-group">
                    <label class="form-label"><i class="fa-solid fa-user-shield"></i> Tài khoản Quản Trị</label>
                    <input type="text" name="username" class="form-input" required autocomplete="username" placeholder="Nhập tài khoản admin">
                </div>
                <div class="form-group">
                    <label class="form-label"><i class="fa-solid fa-lock"></i> Mật khẩu Quản Trị</label>
                    <input type="password" name="password" class="form-input" required autocomplete="current-password" placeholder="Nhập mật khẩu admin">
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px; justify-content: center; font-size: 14px; font-weight: 700; margin-top: 10px;">
                    <i class="fa-solid fa-right-to-bracket"></i> ĐĂNG NHẬP HỆ THỐNG
                </button>
            </form>
            <div style="margin-top: 14px; font-size: 11.5px; color: #94a3b8; background: rgba(6, 182, 212, 0.08); border: 1px solid rgba(6, 182, 212, 0.25); padding: 8px 10px; border-radius: 8px;">
                <i class="fa-solid fa-laptop-code" style="color: #22d3ee;"></i> Bảo mật 1 Thiết Bị: Mỗi tài khoản chỉ được phép đăng nhập cố định trên 1 thiết bị (HWID).
            </div>
            <div style="text-align: center; margin-top: 18px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px;">
                <a href="https://tobivn.chickenkiller.com/" target="_blank" style="color: #22d3ee; text-decoration: none; font-size: 12.5px; font-weight: 600;">
                    <i class="fa-solid fa-globe"></i> Tobi AIM Server Key
                </a>
            </div>
        </div>
    </div>
    <script>
        (function() {
            function computeAdminDeviceFp() {
                var lid = '';
                try {
                    lid = localStorage.getItem('tobiaim_srv_local_id') || '';
                    if (!lid) {
                        if (window.crypto && window.crypto.getRandomValues) {
                            var buf = new Uint8Array(16);
                            window.crypto.getRandomValues(buf);
                            lid = Array.from(buf, function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
                        } else {
                            lid = String(Date.now()) + '-' + Math.random().toString(36).slice(2) + '-' + Math.random().toString(36).slice(2);
                        }
                        localStorage.setItem('tobiaim_srv_local_id', lid);
                    }
                } catch (e) {
                    lid = 'nolocal';
                }
                var tz = '';
                try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}
                var fp = [
                    lid,
                    navigator.platform || '',
                    (screen && screen.width ? screen.width : 0) + 'x' + (screen && screen.height ? screen.height : 0),
                    navigator.hardwareConcurrency || 0,
                    tz
                ].join('|');
                var el = document.getElementById('adminDeviceFp');
                if (el) el.value = fp;
            }
            computeAdminDeviceFp();
            var form = document.getElementById('adminLoginForm');
            if (form) {
                form.addEventListener('submit', computeAdminDeviceFp);
            }
        })();
    </script>

<?php else: ?>
    <nav class="admin-nav">
        <div class="nav-brand">
            <i class="fa-solid fa-server" style="color: var(--primary);"></i>
            <span><?= htmlspecialchars($settings['app_name']) ?> <span style="font-size: 11px; color: var(--accent-cyan); font-weight: normal;">Control Center</span></span>
        </div>
        <div class="nav-links">
            <span style="font-size: 12.5px; color: #cbd5e1; display: inline-flex; align-items: center; gap: 6px; margin-right: 6px;">
                <i class="fa-solid fa-user-shield" style="color: #34d399;"></i>
                <strong style="color: #fff;"><?= htmlspecialchars($_SESSION['admin_current_user'] ?? $settings['admin_user']) ?></strong>
            </span>
            <a href="https://tobivn.chickenkiller.com/" target="_blank" class="nav-btn"><i class="fa-solid fa-globe"></i> Tobi AIM</a>
            <a href="admin.php?action=logout" class="nav-btn logout"><i class="fa-solid fa-power-off"></i> Đăng Xuất</a>
        </div>
    </nav>

    <div class="container">
        <?php if (!empty($msg)): ?>
            <div class="alert alert-success"><i class="fa-solid fa-check"></i> <?= htmlspecialchars($msg) ?></div>
        <?php endif; ?>
        <?php if (!empty($error)): ?>
            <div class="alert alert-error"><i class="fa-solid fa-exclamation-triangle"></i> <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div>
                    <div class="stat-lbl">Tổng Tài Khoản</div>
                    <div class="stat-val"><?= $totalUsers ?></div>
                </div>
                <div class="stat-icon icon-purple"><i class="fa-solid fa-users"></i></div>
            </div>
            <div class="stat-card">
                <div>
                    <div class="stat-lbl">Kho Key Khả Dụng</div>
                    <div class="stat-val"><?= $unusedKeys ?> <span style="font-size: 13px; color: var(--text-muted); font-weight: normal;">/ <?= $totalKeys ?></span></div>
                </div>
                <div class="stat-icon icon-cyan"><i class="fa-solid fa-key"></i></div>
            </div>
            <div class="stat-card">
                <div>
                    <div class="stat-lbl">Thiết Bị Đang Kết Nối</div>
                    <div class="stat-val"><?= $totalConnectedDevices ?></div>
                </div>
                <div class="stat-icon icon-green"><i class="fa-solid fa-mobile-screen"></i></div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('keysTab', this)"><i class="fa-solid fa-key"></i> Tạo & Quản Lý 5 Loại Key</button>
            <button class="tab-btn" onclick="switchTab('securityTab', this)">
                <i class="fa-solid fa-shield-halved"></i> Server & Cập Nhật
                <?php if (!$isServerOpenGlobal): ?>
                    <span class="badge badge-blocked" style="margin-left:4px;">CLOSED</span>
                <?php elseif (!empty($settings['force_update'])): ?>
                    <span class="badge" style="background:rgba(245,158,11,0.2);color:#fbbf24;margin-left:4px;">UPDATE</span>
                <?php endif; ?>
            </button>
            <button class="tab-btn" onclick="switchTab('usersTab', this)"><i class="fa-solid fa-users-gear"></i> Quản Lý Tài Khoản</button>
            <button class="tab-btn" onclick="switchTab('settingsTab', this)"><i class="fa-solid fa-sliders"></i> Cài Đặt Hệ Thống</button>
            <button class="tab-btn" onclick="switchTab('logsTab', this)"><i class="fa-solid fa-clock-rotate-left"></i> Nhật Ký Bảo Mật</button>
        </div>

        <!-- TAB 1: 5 LOẠI KEY -->
        <div id="keysTab" class="tab-pane">
            <div class="content-card">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-plus-circle"></i> Tạo Mã Key Bản Quyền (Tùy Chỉnh Giới Hạn Thiết Bị)</span>
                </div>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="create_key">
                    <div class="form-row">
                        <div>
                            <label class="form-label">Chọn Loại Thời Hạn</label>
                            <select name="key_duration" class="form-select" style="font-weight: 700; color: #22d3ee;">
                                <option value="1h">⚡ 1 Giờ (Dùng thử ngắn hạn)</option>
                                <option value="1d">⭐ 1 Ngày (24 Giờ)</option>
                                <option value="7d">🔥 7 Ngày (1 Tuần)</option>
                                <option value="30d" selected>💎 30 Ngày (1 Tháng)</option>
                                <option value="permanent">👑 Vĩnh Viễn (Lifetime Trọn Đời)</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label">Số Thiết Bị Tối Đa (Max Devices)</label>
                            <select name="max_devices" class="form-select" style="font-weight: 700; color: #34d399;">
                                <option value="1" selected>📱 1 Thiết bị (Mặc định)</option>
                                <option value="2">📱📱 2 Thiết bị (Gói 2 máy)</option>
                                <option value="3">📱 3 Thiết bị</option>
                                <option value="5">📱 5 Thiết bị</option>
                                <option value="10">📱 10 Thiết bị</option>
                                <option value="0">🌐 Không giới hạn thiết bị</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label">Gói Bản Quyền</label>
                            <select name="key_role" class="form-select">
                                <option value="vip">VIP Member (Toàn bộ tính năng)</option>
                                <option value="member">Thành Viên Thường</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label">Số Lượng Key Cần Tạo</label>
                            <input type="number" name="quantity" class="form-input" value="1" min="1" max="50">
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary"><i class="fa-solid fa-key"></i> Sinh Mã Key Ngay</button>
                </form>
            </div>

            <?php if (!empty($newlyCreatedKeys)): 
                $allKeysText = implode("\n", $newlyCreatedKeys);
            ?>
                <!-- BẢNG MÃ KEY VỪA TẠO & NÚT SAO CHÉP TẤT CẢ -->
                <div id="newlyCreatedKeysCard" class="content-card" style="border: 2px solid #a855f7; box-shadow: 0 0 30px rgba(168, 85, 247, 0.4); background: linear-gradient(180deg, rgba(168, 85, 247, 0.16) 0%, var(--bg-surface) 100%); margin-bottom: 24px;">
                    <div class="card-header" style="border-bottom: 1px solid rgba(168, 85, 247, 0.3); padding-bottom: 14px; margin-bottom: 16px;">
                        <div>
                            <span class="card-title" style="color: #f3e8ff; font-size: 17px; font-weight: 800;">
                                <i class="fa-solid fa-circle-check" style="color: #34d399; font-size: 20px;"></i>
                                Danh Sách <?= count($newlyCreatedKeys) ?> Mã Key Vừa Tạo Mới
                            </span>
                            <div style="font-size: 12.5px; color: var(--text-muted); margin-top: 5px;">
                                Thời hạn: <strong style="color: #38bdf8;"><?= htmlspecialchars($newlyCreatedMeta['duration'] ?? '') ?></strong> • 
                                Giới hạn: <strong style="color: #34d399;"><?= htmlspecialchars($newlyCreatedMeta['devices'] ?? '') ?></strong> • 
                                Gói: <span class="badge badge-vip"><?= htmlspecialchars($newlyCreatedMeta['role'] ?? 'VIP') ?></span>
                            </div>
                        </div>

                        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                            <!-- NÚT SAO CHÉP TẤT CẢ KEY VỪA TẠO -->
                            <button type="button" class="btn btn-primary" id="copyAllKeysBtn" onclick="copyAllCreatedKeys()" style="background: linear-gradient(135deg, #9333ea, #06b6d4); font-weight: 700; padding: 9px 18px; font-size: 13.5px; box-shadow: 0 4px 15px rgba(147, 51, 234, 0.45); cursor: pointer;">
                                <i class="fa-solid fa-copy"></i> Sao Chép Tất Cả Key Vừa Tạo (<?= count($newlyCreatedKeys) ?>)
                            </button>

                            <button type="button" class="btn btn-sm" style="background: rgba(255,255,255,0.08); color: var(--text-muted);" onclick="document.getElementById('newlyCreatedKeysCard').style.display='none'" title="Đóng bảng này">
                                <i class="fa-solid fa-xmark"></i> Đóng
                            </button>
                        </div>
                    </div>

                    <!-- Khung xem nhanh danh sách key (mỗi key 1 dòng) -->
                    <div style="margin-bottom: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <label class="form-label" style="margin-bottom: 0; font-size: 11.5px; color: #cbd5e1;">
                                <i class="fa-solid fa-list"></i> Danh sách dạng văn bản (Click vào để bôi đen toàn bộ):
                            </label>
                            <span style="font-size: 11px; color: var(--text-muted);"><?= count($newlyCreatedKeys) ?> dòng</span>
                        </div>
                        <textarea id="allCreatedKeysTextarea" readonly style="width: 100%; height: <?= min(200, max(72, count($newlyCreatedKeys) * 26 + 22)) ?>px; background: rgba(0,0,0,0.45); border: 1px solid rgba(168, 85, 247, 0.3); border-radius: var(--radius-md); padding: 10px 14px; color: #22d3ee; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; line-height: 1.6; resize: vertical; outline: none;" onclick="this.select();"><?= htmlspecialchars($allKeysText) ?></textarea>
                    </div>

                    <!-- Bảng chi tiết từng key vừa tạo -->
                    <div class="table-responsive" style="max-height: 320px; overflow-y: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th style="width: 50px;">STT</th>
                                    <th style="min-width: 250px;">MÃ KEY</th>
                                    <th>THỜI HẠN</th>
                                    <th>GIỚI HẠN MÁY</th>
                                    <th>GÓI</th>
                                    <th style="text-align: right;">THAO TÁC</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($newlyCreatedKeys as $i => $nKey): ?>
                                    <tr>
                                        <td style="color: var(--text-muted); font-size: 12px; font-weight: 700;">#<?= $i + 1 ?></td>
                                        <td>
                                            <strong class="code-box" style="font-size: 13px; border-color: rgba(168, 85, 247, 0.45); color: #f3e8ff; background: rgba(147, 51, 234, 0.2);"><?= htmlspecialchars($nKey) ?></strong>
                                        </td>
                                        <td><strong style="color: #38bdf8;"><?= htmlspecialchars($newlyCreatedMeta['duration'] ?? '') ?></strong></td>
                                        <td><span style="color: #34d399; font-weight: 700;"><?= htmlspecialchars($newlyCreatedMeta['devices'] ?? '') ?></span></td>
                                        <td><span class="badge badge-vip"><?= htmlspecialchars($newlyCreatedMeta['role'] ?? 'VIP') ?></span></td>
                                        <td style="text-align: right;">
                                            <button type="button" class="btn btn-sm" style="padding: 5px 12px; background: rgba(255,255,255,0.08); color: #fff;" onclick="navigator.clipboard.writeText('<?= addslashes($nKey) ?>'); const o=this.innerHTML; this.innerHTML='<i class=\'fa-solid fa-check\' style=\'color: #34d399;\'></i> Đã chép'; setTimeout(()=>this.innerHTML=o, 1500);" title="Sao chép riêng key này">
                                                <i class="fa-regular fa-copy"></i> Sao chép
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php endif; ?>

            <div class="content-card">
                <div class="card-header">
                    <span class="card-title">
                        <i class="fa-solid fa-list-check"></i> Kho Mã Key Đã Tạo & Quản Lý Thiết Bị 
                        <span id="keyCountBadge" class="badge badge-member" style="font-size: 11.5px; margin-left: 8px;">
                            <?= count($allKeys) ?> key
                        </span>
                    </span>
                    <form method="POST" style="display:inline;" onsubmit="return confirm('CẢNH BÁO: Reset toàn bộ thiết bị của TẤT CẢ các key trong hệ thống? Khách hàng sẽ được phép kích hoạt lại trên máy mới.');">
                        <?= csrfField() ?>
                        <input type="hidden" name="action" value="reset_all_keys">
                        <button type="submit" class="btn btn-warning btn-sm" title="Reset tất cả thiết bị của mọi key">
                            <i class="fa-solid fa-arrows-rotate"></i> Reset Tất Cả Thiết Bị
                        </button>
                    </form>
                </div>

                <!-- THANH TÌM KIẾM VÀ BỘ LỌC KEY THÔNG MINH -->
                <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: var(--radius-md); padding: 12px 14px; margin-bottom: 18px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; justify-content: space-between;">
                    <div style="display: flex; gap: 10px; align-items: center; flex: 1; min-width: 260px; max-width: 520px; position: relative;">
                        <i class="fa-solid fa-magnifying-glass" style="position: absolute; left: 12px; color: var(--text-muted); font-size: 13px; pointer-events: none;"></i>
                        <input type="text" id="searchKeyInput" class="form-input" placeholder="Tìm theo mã key, HWID thiết bị, gói..." style="padding-left: 36px; padding-right: 32px; height: 38px; font-size: 13px;" value="<?= htmlspecialchars($keySearch) ?>" oninput="filterKeys()" autocomplete="off">
                        <button type="button" id="clearSearchKeyBtn" style="position: absolute; right: 10px; background: none; border: none; color: var(--text-muted); cursor: pointer; display: none; padding: 4px;" title="Xóa tìm kiếm" onclick="clearKeySearch()">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>

                    <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                        <!-- Lọc trạng thái -->
                        <select id="filterKeyStatus" class="form-select" style="width: auto; height: 38px; font-size: 12.5px; padding: 0 12px;" onchange="filterKeys()">
                            <option value="all">⚡ Tất cả trạng thái</option>
                            <option value="unused">✨ Chưa dùng (0 máy)</option>
                            <option value="in_use">📱 Đang dùng</option>
                            <option value="full">🔒 Đã đủ máy</option>
                            <option value="infinite">♾️ Vô hạn máy</option>
                        </select>

                        <!-- Lọc thời hạn -->
                        <select id="filterKeyDuration" class="form-select" style="width: auto; height: 38px; font-size: 12.5px; padding: 0 12px;" onchange="filterKeys()">
                            <option value="all">⏱️ Tất cả thời hạn</option>
                            <option value="permanent">Vĩnh Viễn</option>
                            <option value="30d">30 Ngày</option>
                            <option value="7d">7 Ngày</option>
                            <option value="1d">1 Ngày</option>
                            <option value="1h">1 Giờ</option>
                        </select>

                        <button type="button" class="btn btn-sm" onclick="resetKeyFilters()" style="height: 38px; background: rgba(255,255,255,0.06); color: var(--text-muted);" title="Làm mới bộ lọc">
                            <i class="fa-solid fa-rotate-left"></i>
                        </button>
                    </div>
                </div>

                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th style="white-space: nowrap; min-width: 240px;">MÃ KEY</th>
                                <th>LOẠI THỜI HẠN</th>
                                <th>GÓI</th>
                                <th>TRẠNG THÁI & GIỚI HẠN</th>
                                <th>THIẾT BỊ ĐÃ KÍCH HOẠT (HWID)</th>
                                <th>NGÀY TẠO</th>
                                <th>THAO TÁC</th>
                            </tr>
                        </thead>
                        <tbody id="keysTableBody">
                            <?php if (empty($allKeys)): ?>
                                <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">Chưa có mã key nào. Hãy chọn loại key ở trên để tạo.</td></tr>
                            <?php else: foreach (array_reverse($allKeys) as $k): 
                                $devCount = isset($k['devices']) && is_array($k['devices']) ? count($k['devices']) : 0;
                                $maxDev = isset($k['max_devices']) ? intval($k['max_devices']) : 1;
                                $hwidsJoined = '';
                                if (!empty($k['devices']) && is_array($k['devices'])) {
                                    $hwidsJoined = implode(' ', array_column($k['devices'], 'hwid'));
                                }
                                $statusSlug = 'in_use';
                                if ($maxDev === 0) {
                                    $statusSlug = 'infinite';
                                } elseif ($devCount === 0) {
                                    $statusSlug = 'unused';
                                } elseif ($devCount >= $maxDev) {
                                    $statusSlug = 'full';
                                }
                            ?>
                                <tr class="key-row" 
                                    data-key="<?= strtolower(htmlspecialchars($k['key'])) ?>"
                                    data-duration="<?= strtolower(htmlspecialchars($k['duration'] ?? ($k['days'] ?? ''))) ?>"
                                    data-role="<?= strtolower(htmlspecialchars($k['role'] ?? 'vip')) ?>"
                                    data-status="<?= $statusSlug ?>"
                                    data-hwids="<?= strtolower(htmlspecialchars($hwidsJoined)) ?>"
                                >
                                    <td style="white-space: nowrap;">
                                        <div style="display: inline-flex; align-items: center; gap: 6px;">
                                            <strong class="code-box"><?= htmlspecialchars($k['key']) ?></strong>
                                            <button type="button" class="btn btn-sm" style="padding: 4px 7px; background: rgba(255,255,255,0.06); color: var(--text-muted); border-radius: 5px;" title="Sao chép key" onclick="navigator.clipboard.writeText('<?= addslashes($k['key']) ?>'); const orig = this.innerHTML; this.innerHTML='<i class=\'fa-solid fa-check\' style=\'color: #34d399;\'></i>'; setTimeout(() => this.innerHTML = orig, 1500);">
                                                <i class="fa-regular fa-copy"></i>
                                            </button>
                                        </div>
                                    </td>
                                    <td>
                                        <strong style="color: #38bdf8;">
                                            <?= formatDurationLabel($k['duration'] ?? ($k['days'] ?? 30)) ?>
                                        </strong>
                                    </td>
                                    <td><span class="badge badge-vip"><?= strtoupper($k['role'] ?? 'VIP') ?></span></td>
                                    <td>
                                        <?php if ($maxDev === 0): ?>
                                            <span class="badge" style="background: rgba(168,85,247,0.2); color:#c084fc;">
                                                <i class="fa-solid fa-infinity"></i> Vô hạn (<?= $devCount ?> máy)
                                            </span>
                                        <?php elseif ($devCount === 0): ?>
                                            <span class="badge badge-active"><i class="fa-solid fa-sparkles"></i> Chưa dùng (0/<?= $maxDev ?>)</span>
                                        <?php elseif ($devCount < $maxDev): ?>
                                            <span class="badge" style="background: rgba(6,182,212,0.15); color:#22d3ee;">
                                                <i class="fa-solid fa-mobile-screen"></i> Đang dùng (<?= $devCount ?>/<?= $maxDev ?>)
                                            </span>
                                        <?php else: ?>
                                            <span class="badge" style="background: rgba(239,68,68,0.2); color:#f87171;">
                                                <i class="fa-solid fa-lock"></i> Đã đủ (<?= $devCount ?>/<?= $maxDev ?>)
                                            </span>
                                        <?php endif; ?>

                                        <!-- Điều chỉnh số thiết bị tối đa trực tiếp -->
                                        <div style="margin-top: 8px;">
                                            <form method="POST" style="display:inline-flex; align-items:center; gap: 4px;" title="Đổi giới hạn thiết bị cho key này">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="update_key_max_devices">
                                                <input type="hidden" name="key" value="<?= htmlspecialchars($k['key']) ?>">
                                                <select name="max_devices" class="form-select" style="padding: 3px 6px; font-size: 11px; width: auto; height: 26px;">
                                                    <option value="1" <?= $maxDev === 1 ? 'selected' : '' ?>>1 máy</option>
                                                    <option value="2" <?= $maxDev === 2 ? 'selected' : '' ?>>2 máy</option>
                                                    <option value="3" <?= $maxDev === 3 ? 'selected' : '' ?>>3 máy</option>
                                                    <option value="5" <?= $maxDev === 5 ? 'selected' : '' ?>>5 máy</option>
                                                    <option value="10" <?= $maxDev === 10 ? 'selected' : '' ?>>10 máy</option>
                                                    <option value="0" <?= $maxDev === 0 ? 'selected' : '' ?>>Vô hạn</option>
                                                </select>
                                                <button type="submit" class="btn btn-primary btn-sm" style="padding: 3px 7px; font-size: 10px;" title="Lưu số máy"><i class="fa-solid fa-floppy-disk"></i></button>
                                            </form>
                                        </div>
                                    </td>
                                    <td>
                                        <?php if (empty($k['devices'])): ?>
                                            <span style="color:#64748b; font-size: 12px;"><i class="fa-solid fa-circle-minus"></i> Chưa có máy nào</span>
                                        <?php else: ?>
                                            <div style="display: flex; flex-direction: column; gap: 6px; max-width: 390px;">
                                                <?php foreach ($k['devices'] as $d):
                                                    $devHwid = trim((string)($d['hwid'] ?? ''));
                                                    $banInfo = $bannedHwidMap[strtolower($devHwid)] ?? null;
                                                ?>
                                                    <div style="background: <?= $banInfo ? 'rgba(239,68,68,0.1)' : 'rgba(255,255,255,0.03)' ?>; border: 1px solid <?= $banInfo ? 'rgba(239,68,68,0.45)' : 'rgba(255,255,255,0.08)' ?>; border-radius: 6px; padding: 6px 8px; display: flex; justify-content: space-between; align-items: center; gap: 6px;">
                                                        <div style="overflow: hidden; flex: 1;">
                                                            <div style="font-family: monospace; font-size: 11px; color: <?= $banInfo ? '#f87171' : '#38bdf8' ?>; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="<?= htmlspecialchars($devHwid) ?>">
                                                                <i class="fa-solid fa-mobile-screen-button"></i> <?= htmlspecialchars($devHwid) ?>
                                                                <?php if ($banInfo): ?>
                                                                    <span class="badge badge-blocked" style="font-size:9px;padding:2px 6px;margin-left:4px;">ĐÃ BAN</span>
                                                                <?php endif; ?>
                                                            </div>
                                                            <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">
                                                                Kích hoạt: <?= htmlspecialchars($d['activated_at'] ?? 'N/A') ?>
                                                                <?php if ($banInfo && !empty($banInfo['reason'])): ?>
                                                                    · Lý do: <?= htmlspecialchars($banInfo['reason']) ?>
                                                                <?php endif; ?>
                                                            </div>
                                                        </div>
                                                        <div style="display:flex;gap:4px;flex-shrink:0;align-items:center;">
                                                            <?php if ($banInfo): ?>
                                                                <form method="POST" style="margin: 0;" onsubmit="return confirm('Gỡ Ban cho thiết bị HWID này?');">
                                                                    <?= csrfField() ?>
                                                                    <input type="hidden" name="action" value="unban_device">
                                                                    <input type="hidden" name="return_tab" value="keysTab">
                                                                    <input type="hidden" name="hwid" value="<?= htmlspecialchars($devHwid) ?>">
                                                                    <button type="submit" class="btn btn-primary btn-sm" style="padding: 3px 6px; font-size: 10px;" title="Gỡ Ban HWID này"><i class="fa-solid fa-unlock"></i> Gỡ Ban</button>
                                                                </form>
                                                            <?php else: ?>
                                                                <form method="POST" style="margin: 0;" onsubmit="return promptBanReason(this, '<?= htmlspecialchars($devHwid, ENT_QUOTES) ?>');">
                                                                    <?= csrfField() ?>
                                                                    <input type="hidden" name="action" value="ban_device">
                                                                    <input type="hidden" name="return_tab" value="keysTab">
                                                                    <input type="hidden" name="hwid" value="<?= htmlspecialchars($devHwid) ?>">
                                                                    <input type="hidden" name="source_key" value="<?= htmlspecialchars($k['key']) ?>">
                                                                    <input type="hidden" name="reason" value="">
                                                                    <button type="submit" class="btn btn-sm" style="padding: 3px 6px; font-size: 10px; background: rgba(245,158,11,0.18); color: #fbbf24; border: 1px solid rgba(245,158,11,0.35);" title="Ban vĩnh viễn thiết bị theo HWID này"><i class="fa-solid fa-ban"></i> Ban</button>
                                                                </form>
                                                            <?php endif; ?>
                                                            <form method="POST" style="margin: 0;" onsubmit="return confirm('Ngắt kết nối thiết bị này? Máy này sẽ không còn quyền dùng key.');">
                                                                <?= csrfField() ?>
                                                                <input type="hidden" name="action" value="remove_key_device">
                                                                <input type="hidden" name="key" value="<?= htmlspecialchars($k['key']) ?>">
                                                                <input type="hidden" name="hwid" value="<?= htmlspecialchars($devHwid) ?>">
                                                                <button type="submit" class="btn btn-danger btn-sm" style="padding: 3px 6px; font-size: 10px;" title="Xóa thiết bị này (Kick máy)"><i class="fa-solid fa-xmark"></i> Xóa</button>
                                                            </form>
                                                        </div>
                                                    </div>
                                                <?php endforeach; ?>
                                            </div>
                                        <?php endif; ?>
                                    </td>
                                    <td style="font-size: 11.5px; color: var(--text-muted);"><?= htmlspecialchars($k['created_at'] ?? 'N/A') ?></td>
                                    <td style="white-space: nowrap;">
                                        <?php $isKeyRevoked = in_array(strtolower((string)($k['status'] ?? 'active')), ['revoked', 'banned', 'disabled'], true); ?>
                                        <form method="POST" style="display:inline-block; margin-right: 4px;">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="toggle_key_status">
                                            <input type="hidden" name="key" value="<?= htmlspecialchars($k['key']) ?>">
                                            <button type="submit" class="btn btn-sm <?= $isKeyRevoked ? 'btn-primary' : 'btn-danger' ?>" title="<?= $isKeyRevoked ? 'Mở khóa Key' : 'Khóa/Thu hồi Key' ?>">
                                                <i class="fa-solid <?= $isKeyRevoked ? 'fa-unlock' : 'fa-ban' ?>"></i>
                                            </button>
                                        </form>
                                        <form method="POST" style="display:inline-block; margin-right: 4px;" onsubmit="return confirm('Reset mã key <?= htmlspecialchars($k['key']) ?>? Toàn bộ thiết bị đã liên kết sẽ bị xóa và thời hạn sẽ được làm mới.');">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="reset_key">
                                            <input type="hidden" name="key" value="<?= htmlspecialchars($k['key']) ?>">
                                            <button type="submit" class="btn btn-warning btn-sm" title="Reset Key (xóa máy & làm mới)"><i class="fa-solid fa-arrows-rotate"></i> Reset</button>
                                        </form>
                                        <form method="POST" style="display:inline-block;" onsubmit="return confirm('Xóa vĩnh viễn key này?');">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="delete_key">
                                            <input type="hidden" name="key" value="<?= htmlspecialchars($k['key']) ?>">
                                            <button type="submit" class="btn btn-danger btn-sm" title="Xóa key"><i class="fa-solid fa-trash"></i></button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; endif; ?>
                            <tr id="noKeyMatchRow" style="display: none;">
                                <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">
                                    <i class="fa-solid fa-magnifying-glass" style="font-size: 20px; margin-bottom: 8px; display: block; color: #64748b;"></i>
                                    Không tìm thấy mã key nào phù hợp với điều kiện tìm kiếm.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB SECURITY: KILL-SWITCH, FORCE UPDATE & BUILD MANIFESTS -->
        <div id="securityTab" class="tab-pane" style="display: none;">
            <div class="content-card" style="border: 1px solid <?= $isServerOpenGlobal ? 'rgba(16,185,129,0.35)' : 'rgba(239,68,68,0.55)' ?>;">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-power-off"></i> Công Tắc Đóng/Mở Server & Ép Cập Nhật (Toàn Hệ Thống)</span>
                    <span class="badge <?= $isServerOpenGlobal ? 'badge-active' : 'badge-blocked' ?>">
                        <?= $isServerOpenGlobal ? 'SERVER ĐANG MỞ' : 'SERVER ĐANG ĐÓNG KHẨN CẤP' ?>
                    </span>
                </div>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="update_security_policy">
                    <div class="form-row">
                        <div>
                            <label class="form-label">Trạng Thái Server (Kill-Switch)</label>
                            <label style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg-input);border-radius:var(--radius-md);border:1px solid rgba(255,255,255,0.1);cursor:pointer;">
                                <input type="checkbox" name="server_open" value="1" <?= $isServerOpenGlobal ? 'checked' : '' ?>>
                                <strong>Mở Server cho phép xác thực & cấp khóa phiên</strong>
                            </label>
                        </div>
                        <div>
                            <label class="form-label">Ép Cập Nhật (Force Update)</label>
                            <label style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg-input);border-radius:var(--radius-md);border:1px solid rgba(255,255,255,0.1);cursor:pointer;">
                                <input type="checkbox" name="force_update" value="1" <?= !empty($settings['force_update']) ? 'checked' : '' ?>>
                                <strong>Chặn các bản cũ hơn bản mới nhất (Latest Version)</strong>
                            </label>
                        </div>
                        <div>
                            <label class="form-label">Kiểm Tra Chữ Ký Binary</label>
                            <label style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg-input);border-radius:var(--radius-md);border:1px solid rgba(255,255,255,0.1);cursor:pointer;">
                                <input type="checkbox" name="enforce_binary_hash" value="1" <?= !empty($settings['enforce_binary_hash']) ? 'checked' : '' ?>>
                                <strong>Từ chối App nếu sai SHA-256 __TEXT (Anti-Patch)</strong>
                            </label>
                        </div>
                    </div>

                    <div class="form-row">
                        <div>
                            <label class="form-label">Phiên bản Tối Thiểu (min_required_version)</label>
                            <input type="text" name="min_required_version" class="form-input" value="<?= htmlspecialchars($settings['min_required_version'] ?? '2.1.0') ?>" placeholder="2.1.0">
                        </div>
                        <div>
                            <label class="form-label">Phiên bản Mới Nhất (latest_version)</label>
                            <input type="text" name="latest_version" class="form-input" value="<?= htmlspecialchars($settings['latest_version'] ?? '2.1.0') ?>" placeholder="2.1.0">
                        </div>
                        <div>
                            <label class="form-label">Link Tải Bản Mới (download_url)</label>
                            <input type="url" name="download_url" class="form-input" value="<?= htmlspecialchars($settings['download_url'] ?? '') ?>" placeholder="https://tobivn.chickenkiller.com/download">
                        </div>
                    </div>

                    <div class="form-row">
                        <div>
                            <label class="form-label">Thông báo khi ĐÓNG Server</label>
                            <input type="text" name="server_closed_message" class="form-input" value="<?= htmlspecialchars($settings['server_closed_message'] ?? '') ?>">
                        </div>
                        <div>
                            <label class="form-label">Thông báo khi ÉP CẬP NHẬT</label>
                            <input type="text" name="update_message" class="form-input" value="<?= htmlspecialchars($settings['update_message'] ?? '') ?>">
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary"><i class="fa-solid fa-shield-check"></i> Lưu Chính Sách Kill-Switch & Update</button>
                </form>
            </div>

            <div class="content-card">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-cubes"></i> Chính Sách Riêng Theo Từng Gói App (Package ID)</span>
                </div>
                <form method="POST" style="margin-bottom: 18px;">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="upsert_package_policy">
                    <div class="form-row">
                        <div>
                            <label class="form-label">Package / Bundle ID</label>
                            <input type="text" name="package_id" class="form-input" value="com.apple.mobile.MobileHouseArrest" required>
                        </div>
                        <div>
                            <label class="form-label">Min Version</label>
                            <input type="text" name="pkg_min_version" class="form-input" placeholder="2.1.0">
                        </div>
                        <div>
                            <label class="form-label">Latest Version</label>
                            <input type="text" name="pkg_latest_version" class="form-input" placeholder="2.1.0">
                        </div>
                        <div>
                            <label class="form-label">Download URL</label>
                            <input type="url" name="pkg_download_url" class="form-input" placeholder="https://...">
                        </div>
                    </div>
                    <div class="form-row">
                        <div>
                            <label class="form-label">Thông báo đóng gói riêng</label>
                            <input type="text" name="pkg_closed_message" class="form-input" placeholder="Gói này đang tạm đóng...">
                        </div>
                        <div>
                            <label class="form-label">Thông báo cập nhật gói</label>
                            <input type="text" name="pkg_update_message" class="form-input" placeholder="Vui lòng cập nhật gói...">
                        </div>
                        <div style="display:flex;flex-direction:column;justify-content:center;gap:6px;">
                            <label><input type="checkbox" name="pkg_server_open" value="1" checked> Mở gói này</label>
                            <label><input type="checkbox" name="pkg_force_update" value="1"> Ép update gói</label>
                            <label><input type="checkbox" name="pkg_enforce_hash" value="1"> Siết Binary Hash</label>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-floppy-disk"></i> Lưu Chính Sách Gói</button>
                </form>

                <?php if (!empty($settings['packages'])): ?>
                    <div class="table-responsive">
                        <table>
                            <thead><tr><th>PACKAGE ID</th><th>SERVER</th><th>MIN / LATEST</th><th>HASH</th><th>THAO TÁC</th></tr></thead>
                            <tbody>
                                <?php foreach ($settings['packages'] as $pkgKey => $pkgCfg): ?>
                                    <tr>
                                        <td><span class="code-box"><?= htmlspecialchars($pkgKey) ?></span></td>
                                        <td><?= !empty($pkgCfg['server_open']) ? '<span class="badge badge-active">MỞ</span>' : '<span class="badge badge-blocked">ĐÓNG</span>' ?></td>
                                        <td><?= htmlspecialchars(($pkgCfg['min_required_version'] ?: '-') . ' / ' . ($pkgCfg['latest_version'] ?: '-')) ?></td>
                                        <td><?= !empty($pkgCfg['enforce_binary_hash']) ? 'Strict' : 'Auto' ?></td>
                                        <td>
                                            <form method="POST" style="display:inline;">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="delete_package_policy">
                                                <input type="hidden" name="package_id" value="<?= htmlspecialchars($pkgKey) ?>">
                                                <button type="submit" class="btn btn-danger btn-sm"><i class="fa-solid fa-trash"></i></button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>

            <div class="content-card">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-sliders"></i> Trạng Thái File Mod (.3105) — Đang Ổn Định / Bảo Trì</span>
                </div>
                <p style="font-size:13px;color:var(--text-muted);margin:0 0 14px 0;">
                    Chỉnh file nào còn dùng được để <strong>Đang ổn định</strong>, file nào lỗi/đang sửa chọn <strong>Bảo trì</strong>. File đặt Bảo trì sẽ tự khóa trên app iOS và không được cấp khóa giải mã từ server.
                </p>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="save_preset_policies">
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>TÊN MOD / FILE</th>
                                    <th>TRẠNG THÁI</th>
                                    <th>CHẾ ĐỘ HOẠT ĐỘNG</th>
                                    <th>THÔNG BÁO BẢO TRÌ (HIỆN TRÊN APP)</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($presetPoliciesView as $pItem):
                                    $pFile = $pItem['file_name'];
                                    $pLabel = $pItem['label'];
                                    $isMaint = ($pItem['status'] === 'maintenance');
                                    $rawMsg = trim((string)(($settings['preset_policies'][$pFile]['message'] ?? '')));
                                ?>
                                    <tr>
                                        <td>
                                            <strong><?= htmlspecialchars($pLabel) ?></strong>
                                            <div style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars($pFile) ?></div>
                                        </td>
                                        <td>
                                            <?= $isMaint
                                                ? '<span class="badge badge-blocked">Đang bảo trì</span>'
                                                : '<span class="badge badge-active">Đang ổn định</span>' ?>
                                        </td>
                                        <td>
                                            <select name="preset_status[<?= htmlspecialchars($pFile) ?>]" class="form-input" style="min-width:165px;">
                                                <option value="stable" <?= !$isMaint ? 'selected' : '' ?>>Đang ổn định</option>
                                                <option value="maintenance" <?= $isMaint ? 'selected' : '' ?>>Bảo trì (Tạm khóa)</option>
                                            </select>
                                        </td>
                                        <td>
                                            <input type="text" name="preset_message[<?= htmlspecialchars($pFile) ?>]" class="form-input" value="<?= htmlspecialchars($rawMsg) ?>" placeholder="VD: Đang bảo trì cập nhật sau bản vá game...">
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <div style="margin-top:14px;">
                        <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-floppy-disk"></i> Lưu Trạng Thái File Mod</button>
                    </div>
                </form>
            </div>

            <div class="content-card">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-fingerprint"></i> Build Hash Manifests (SHA-256 __TEXT từ CI/GitHub Actions)</span>
                </div>
                <form method="POST" style="margin-bottom: 18px;">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="add_build_manifest">
                    <div class="form-row">
                        <div><label class="form-label">Package ID</label><input type="text" name="package_id" class="form-input" value="com.apple.mobile.MobileHouseArrest" required></div>
                        <div><label class="form-label">Version</label><input type="text" name="version" class="form-input" placeholder="2.1.0" required></div>
                        <div><label class="form-label">Build</label><input type="text" name="build" class="form-input" placeholder="9"></div>
                    </div>
                    <div class="form-row">
                        <div><label class="form-label">App __TEXT SHA-256 (64 hex)</label><input type="text" name="app_hash" class="form-input" required></div>
                        <div><label class="form-label">libsec_core __TEXT SHA-256 (64 hex)</label><input type="text" name="sec_hash" class="form-input" required></div>
                        <div><label class="form-label">Ghi chú</label><input type="text" name="note" class="form-input" placeholder="CI Release"></div>
                    </div>
                    <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-plus"></i> Đăng Ký Build Hash</button>
                </form>

                <div class="table-responsive">
                    <table>
                        <thead><tr><th>PACKAGE / VER</th><th>APP HASH</th><th>SEC DYLIB HASH</th><th>TRẠNG THÁI</th><th>THAO TÁC</th></tr></thead>
                        <tbody>
                            <?php if (empty($allManifests)): ?>
                                <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px;">Chưa có bản build CI nào được đăng ký.</td></tr>
                            <?php else: foreach ($allManifests as $mIdx => $m): ?>
                                <tr>
                                    <td>
                                        <strong><?= htmlspecialchars($m['version']) ?></strong> (<?= htmlspecialchars($m['build'] ?? '') ?>)
                                        <div style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars($m['package_id']) ?> · <?= htmlspecialchars($m['registered_at'] ?? '') ?></div>
                                    </td>
                                    <td><span class="code-box"><?= htmlspecialchars(substr($m['app_hash'], 0, 16)) ?>...</span></td>
                                    <td><span class="code-box"><?= htmlspecialchars(substr($m['sec_hash'], 0, 16)) ?>...</span></td>
                                    <td><?= empty($m['revoked']) ? '<span class="badge badge-active">Hợp lệ</span>' : '<span class="badge badge-blocked">Đã thu hồi</span>' ?></td>
                                    <td>
                                        <form method="POST" style="display:inline;">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="toggle_manifest_revoke">
                                            <input type="hidden" name="manifest_idx" value="<?= $mIdx ?>">
                                            <button type="submit" class="btn btn-sm <?= empty($m['revoked']) ? 'btn-danger' : 'btn-primary' ?>"><?= empty($m['revoked']) ? 'Thu hồi' : 'Khôi phục' ?></button>
                                        </form>
                                        <form method="POST" style="display:inline;">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="delete_manifest">
                                            <input type="hidden" name="manifest_idx" value="<?= $mIdx ?>">
                                            <button type="submit" class="btn btn-danger btn-sm"><i class="fa-solid fa-trash"></i></button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="content-card" style="border: 1px solid rgba(239,68,68,0.35);">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-ban"></i> Danh Sách Thiết Bị Bị Ban Theo HWID (<?= count($bannedHwidMap) ?>)</span>
                </div>
                <form method="POST" style="margin-bottom: 18px;">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="ban_device">
                    <input type="hidden" name="return_tab" value="securityTab">
                    <div class="form-row">
                        <div>
                            <label class="form-label">Mã HWID / Device Fingerprint cần Ban</label>
                            <input type="text" name="hwid" class="form-input" required placeholder="Nhập UUID hoặc SHA-256 HWID của máy...">
                        </div>
                        <div>
                            <label class="form-label">Lý do khóa (Hiển thị trên App)</label>
                            <input type="text" name="reason" class="form-input" placeholder="Ví dụ: Crack / Can thiệp hệ thống / Share Key">
                        </div>
                    </div>
                    <button type="submit" class="btn btn-danger btn-sm"><i class="fa-solid fa-ban"></i> Ban Thiết Bị Này</button>
                </form>

                <div class="table-responsive">
                    <table>
                        <thead><tr><th>HWID THIẾT BỊ</th><th>LÝ DO KHÓA</th><th>KEY LIÊN QUAN</th><th>NGƯỜI BAN / THỜI GIAN</th><th>THAO TÁC</th></tr></thead>
                        <tbody>
                            <?php if (empty($bannedHwidMap)): ?>
                                <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px;">Chưa có thiết bị nào bị Ban.</td></tr>
                            <?php else: foreach ($bannedHwidMap as $bd): ?>
                                <tr>
                                    <td><span class="code-box" style="color:#f87171;border-color:rgba(239,68,68,0.4);"><?= htmlspecialchars((string)$bd['hwid']) ?></span></td>
                                    <td><?= htmlspecialchars((string)($bd['reason'] ?: 'Không ghi rõ')) ?></td>
                                    <td><?= !empty($bd['source_key']) ? '<span class="code-box">' . htmlspecialchars((string)$bd['source_key']) . '</span>' : '-' ?></td>
                                    <td style="font-size:11.5px;color:var(--text-muted);"><?= htmlspecialchars((string)($bd['banned_by'] ?? 'admin')) ?> · <?= htmlspecialchars((string)($bd['banned_at'] ?? '')) ?></td>
                                    <td>
                                        <form method="POST" style="display:inline;" onsubmit="return confirm('Gỡ Ban cho thiết bị này?');">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="unban_device">
                                            <input type="hidden" name="return_tab" value="securityTab">
                                            <input type="hidden" name="hwid" value="<?= htmlspecialchars((string)$bd['hwid']) ?>">
                                            <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-unlock"></i> Gỡ Ban</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 2: USERS -->
        <div id="usersTab" class="tab-pane" style="display: none;">
            <div class="content-card">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-user-plus"></i> Thêm Tài Khoản Mới Trực Tiếp</span>
                </div>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="add_user">
                    <div class="form-row">
                        <div>
                            <label class="form-label">Tên tài khoản</label>
                            <input type="text" name="username" class="form-input" required placeholder="Tên đăng nhập">
                        </div>
                        <div>
                            <label class="form-label">Mật khẩu</label>
                            <input type="text" name="password" class="form-input" required placeholder="Mật khẩu">
                        </div>
                        <div>
                            <label class="form-label">Hạng thành viên</label>
                            <select name="role" class="form-select">
                                <option value="vip">VIP Member</option>
                                <option value="member">Thành Viên Thường</option>
                                <option value="admin">Quản Trị Viên (Admin)</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label">Thời hạn sử dụng</label>
                            <select name="duration" class="form-select" style="color: #22d3ee; font-weight: 700;">
                                <option value="1h">1 Giờ</option>
                                <option value="1d">1 Ngày</option>
                                <option value="7d">7 Ngày</option>
                                <option value="30d" selected>30 Ngày</option>
                                <option value="permanent">Vĩnh Viễn</option>
                            </select>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary"><i class="fa-solid fa-plus"></i> Tạo Tài Khoản</button>
                </form>
            </div>

            <div class="content-card">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-table-list"></i> Danh Sách Tài Khoản (<?= count($filteredUsers) ?>)</span>
                    <form method="GET" style="display: flex; gap: 8px;">
                        <input type="text" name="q" class="form-input" style="width: 250px; padding: 7px 12px; font-size: 12.5px;" placeholder="Tìm username hoặc HWID..." value="<?= htmlspecialchars($_GET['q'] ?? '') ?>">
                        <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-search"></i> Tìm</button>
                    </form>
                </div>
                <div style="font-size: 12px; color: #94a3b8; margin-bottom: 14px; background: rgba(6, 182, 212, 0.08); border: 1px solid rgba(6, 182, 212, 0.2); border-radius: 8px; padding: 9px 12px;">
                    <i class="fa-solid fa-shield-halved" style="color: #22d3ee;"></i> <strong>Chế độ 1 Tài Khoản = 1 Thiết Bị:</strong> Khi tài khoản đăng nhập lần đầu sẽ tự động khóa chặt vào HWID thiết bị đó. Mọi máy khác đăng nhập cùng tài khoản sẽ bị chặn ngay lập tức cho đến khi bạn bấm nút <strong>Reset HWID</strong> (<i class="fa-solid fa-arrows-rotate"></i>).
                </div>

                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>TÀI KHOẢN</th>
                                <th>VAI TRÒ</th>
                                <th>TRẠNG THÁI</th>
                                <th>THỜI GIAN CÒN LẠI (HIỆN TRONG APP)</th>
                                <th>THIẾT BỊ (HWID)</th>
                                <th>ĐĂNG NHẬP CUỐI</th>
                                <th>THAO TÁC</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($filteredUsers)): ?>
                                <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">Chưa có tài khoản nào trong hệ thống.</td></tr>
                            <?php else: foreach ($filteredUsers as $u): ?>
                                <tr>
                                    <td>
                                        <strong style="color: #fff; font-size: 14px;"><?= htmlspecialchars($u['username']) ?></strong>
                                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Tạo: <?= htmlspecialchars($u['created_at'] ?? 'N/A') ?></div>
                                    </td>
                                    <td>
                                        <?php if (($u['role'] ?? '') === 'admin'): ?>
                                            <span class="badge" style="background: rgba(239,68,68,0.2); color: #f87171;">ADMIN</span>
                                        <?php elseif (($u['role'] ?? '') === 'vip'): ?>
                                            <span class="badge badge-vip">VIP</span>
                                        <?php else: ?>
                                            <span class="badge badge-member">MEMBER</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if (!empty($u['is_active'])): ?>
                                            <span class="badge badge-active"><i class="fa-solid fa-check"></i> Hoạt động</span>
                                        <?php else: ?>
                                            <span class="badge badge-blocked"><i class="fa-solid fa-ban"></i> Đã khóa</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <div style="font-weight: 700; color: #34d399; font-size: 13.5px;">
                                            <i class="fa-solid fa-clock"></i> <?= formatRemainingTime($u['expiry_date'] ?? 'permanent') ?>
                                        </div>
                                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
                                            <?= empty($u['expiry_date']) || $u['expiry_date'] === 'permanent' ? 'Vĩnh viễn' : date('d/m/Y H:i', strtotime($u['expiry_date'])) ?>
                                        </div>
                                    </td>
                                    <td>
                                        <?php if (!empty($u['hwid'])):
                                            $uHwid = trim((string)$u['hwid']);
                                            $uBanned = !empty($bannedHwidMap[strtolower($uHwid)]);
                                            $uLabel = trim((string)($u['device_label'] ?? ''));
                                            $uOnline = !empty($u['active_session_token']);
                                        ?>
                                            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                                                <span class="code-box" style="<?= $uBanned ? 'color:#f87171;border-color:rgba(239,68,68,0.45);' : '' ?>" title="<?= htmlspecialchars($uHwid) ?>"><?= htmlspecialchars(substr($uHwid, 0, 18)) ?><?= strlen($uHwid) > 18 ? '...' : '' ?></span>
                                                <?php if ($uOnline): ?>
                                                    <span class="badge badge-active" style="font-size:10px;padding:2px 6px;">Đang online</span>
                                                <?php endif; ?>
                                                <?php if ($uBanned): ?>
                                                    <form method="POST" style="display:inline;">
                                                        <?= csrfField() ?>
                                                        <input type="hidden" name="action" value="unban_device">
                                                        <input type="hidden" name="return_tab" value="usersTab">
                                                        <input type="hidden" name="hwid" value="<?= htmlspecialchars($uHwid) ?>">
                                                        <button type="submit" class="btn btn-primary btn-sm" style="padding:2px 6px;font-size:10px;">Gỡ Ban</button>
                                                    </form>
                                                <?php else: ?>
                                                    <form method="POST" style="display:inline;" onsubmit="return promptBanReason(this, '<?= htmlspecialchars($uHwid, ENT_QUOTES) ?>');">
                                                        <?= csrfField() ?>
                                                        <input type="hidden" name="action" value="ban_device">
                                                        <input type="hidden" name="return_tab" value="usersTab">
                                                        <input type="hidden" name="hwid" value="<?= htmlspecialchars($uHwid) ?>">
                                                        <input type="hidden" name="reason" value="">
                                                        <button type="submit" class="btn btn-danger btn-sm" style="padding:2px 6px;font-size:10px;"><i class="fa-solid fa-ban"></i> Ban</button>
                                                    </form>
                                                <?php endif; ?>
                                            </div>
                                            <?php if ($uLabel !== ''): ?>
                                                <div style="font-size: 11px; color: #94a3b8; margin-top: 3px;"><i class="fa-solid fa-desktop"></i> <?= htmlspecialchars($uLabel) ?></div>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <span style="color: #64748b; font-size: 11.5px;">(Chưa liên kết)</span>
                                        <?php endif; ?>
                                    </td>
                                    <td style="font-size: 11.5px; color: var(--text-muted);">
                                        <?= htmlspecialchars($u['last_login'] ?? 'Chưa đăng nhập') ?>
                                        <?php if (!empty($u['last_ip'])): ?>
                                            <div style="font-size: 10.5px; color: #64748b; margin-top: 2px;">IP: <?= htmlspecialchars((string)$u['last_ip']) ?></div>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <div style="display: flex; gap: 5px;">
                                            <!-- Khóa / Mở -->
                                            <form method="POST" style="display:inline;">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="toggle_status">
                                                <input type="hidden" name="username" value="<?= htmlspecialchars($u['username']) ?>">
                                                <button type="submit" class="btn btn-sm <?= empty($u['is_active']) ? 'btn-primary' : 'btn-danger' ?>" title="Đổi trạng thái Khóa/Mở">
                                                    <?= empty($u['is_active']) ? '<i class="fa-solid fa-unlock"></i>' : '<i class="fa-solid fa-lock"></i>' ?>
                                                </button>
                                            </form>

                                            <?php if (!empty($u['active_session_token'])): ?>
                                            <!-- Kick phiên đang online (giữ nguyên HWID) -->
                                            <form method="POST" style="display:inline;" onsubmit="return confirm('Đăng xuất phiên hiện tại của <?= htmlspecialchars($u['username']) ?>?');">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="kick_user_session">
                                                <input type="hidden" name="username" value="<?= htmlspecialchars($u['username']) ?>">
                                                <button type="submit" class="btn btn-sm" style="background: rgba(245,158,11,0.18); color: #fbbf24;" title="Đăng xuất phiên hiện tại (giữ HWID)">
                                                    <i class="fa-solid fa-right-from-bracket"></i>
                                                </button>
                                            </form>
                                            <?php endif; ?>

                                            <!-- Reset HWID -->
                                            <form method="POST" style="display:inline;" onsubmit="return confirm('Reset HWID tài khoản <?= htmlspecialchars($u['username']) ?> để liên kết 1 thiết bị mới?');">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="reset_hwid">
                                                <input type="hidden" name="username" value="<?= htmlspecialchars($u['username']) ?>">
                                                <button type="submit" class="btn btn-sm" style="background: rgba(6,182,212,0.15); color: #22d3ee;" title="Reset HWID (cho phép đổi sang 1 máy mới)">
                                                    <i class="fa-solid fa-arrows-rotate"></i>
                                                </button>
                                            </form>

                                            <!-- Xóa User -->
                                            <form method="POST" style="display:inline;" onsubmit="return confirm('Xóa vĩnh viễn tài khoản <?= htmlspecialchars($u['username']) ?>?');">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="delete_user">
                                                <input type="hidden" name="username" value="<?= htmlspecialchars($u['username']) ?>">
                                                <button type="submit" class="btn btn-sm btn-danger" title="Xóa tài khoản">
                                                    <i class="fa-solid fa-trash"></i>
                                                </button>
                                            </form>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 3: SETTINGS -->
        <div id="settingsTab" class="tab-pane" style="display: none;">
            <div class="content-card">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-gears"></i> Cấu Hình Cổng Đăng Ký & Bảo Mật</span>
                </div>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="update_settings">
                    <div class="form-row">
                        <div>
                            <label class="form-label">Tên Ứng Dụng</label>
                            <input type="text" name="app_name" class="form-input" value="<?= htmlspecialchars($settings['app_name']) ?>" required>
                        </div>
                        <div>
                            <label class="form-label">Tài Khoản Admin</label>
                            <input type="text" name="admin_user" class="form-input" value="<?= htmlspecialchars($settings['admin_user']) ?>" required>
                        </div>
                        <div>
                            <label class="form-label">Mật Khẩu Admin Mới <span style="font-weight:normal; color:var(--text-muted);">(Để trống nếu không đổi)</span></label>
                            <input type="password" name="admin_pass" class="form-input" placeholder="Nhập nếu muốn đổi">
                        </div>
                    </div>

                    <div class="form-row">
                        <div>
                            <label class="form-label">Thời hạn mặc định khi đăng ký tự do</label>
                            <select name="default_duration" class="form-select">
                                <option value="1h" <?= ($settings['default_duration'] ?? '') === '1h' ? 'selected' : '' ?>>1 Giờ</option>
                                <option value="1d" <?= ($settings['default_duration'] ?? '') === '1d' ? 'selected' : '' ?>>1 Ngày</option>
                                <option value="7d" <?= ($settings['default_duration'] ?? '') === '7d' ? 'selected' : '' ?>>7 Ngày</option>
                                <option value="30d" <?= ($settings['default_duration'] ?? '') === '30d' || empty($settings['default_duration']) ? 'selected' : '' ?>>30 Ngày</option>
                                <option value="permanent" <?= ($settings['default_duration'] ?? '') === 'permanent' ? 'selected' : '' ?>>Vĩnh Viễn</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label">Link Hỗ Trợ Telegram</label>
                            <input type="text" name="telegram_support" class="form-input" value="<?= htmlspecialchars($settings['telegram_support'] ?? '') ?>" placeholder="https://t.me/...">
                        </div>
                    </div>

                    <div style="margin: 20px 0; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px;">
                        <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px; cursor: pointer;">
                            <input type="checkbox" name="allow_register" value="1" <?= !empty($settings['allow_register']) ? 'checked' : '' ?>>
                            <span><strong>Mở cổng đăng ký tài khoản tự do:</strong> Cho phép thành viên tự đăng ký trên website</span>
                        </label>

                        <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px; cursor: pointer;">
                            <input type="checkbox" name="require_key" value="1" <?= !empty($settings['require_key']) ? 'checked' : '' ?>>
                            <span><strong>Bắt buộc có License Key khi đăng ký:</strong> Chỉ người có mã Key bạn cấp mới đăng ký được</span>
                        </label>

                        <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px; cursor: pointer;">
                            <input type="checkbox" name="bind_hwid" value="1" <?= (!array_key_exists('bind_hwid', $settings) || !empty($settings['bind_hwid'])) ? 'checked' : '' ?>>
                            <span><strong>Khóa 1 tài khoản = 1 thiết bị (HWID):</strong> Tự động gắn cứng HWID ở lần đăng nhập đầu tiên cho mọi tài khoản Server Key (Chống share tài khoản)</span>
                        </label>

                        <label style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px; cursor: pointer;">
                            <input type="checkbox" name="lock_master_hwid" value="1" <?= !empty($settings['lock_master_hwid']) ? 'checked' : '' ?>>
                            <span><strong>Khóa cứng HWID cho tài khoản Master Admin gốc:</strong> Mặc định Master Admin luôn chỉ cho phép 1 phiên đăng nhập đồng thời; bật mục này để khóa cứng luôn vào 1 máy cố định</span>
                        </label>
                    </div>

                    <button type="submit" class="btn btn-primary"><i class="fa-solid fa-save"></i> Lưu Cài Đặt</button>
                </form>
                <?php $masterInfo = readJsonFile(MASTER_SESSION_FILE, []); if (!empty($masterInfo['hwid'])): ?>
                <div style="margin-top: 16px; padding-top: 14px; border-top: 1px solid rgba(255,255,255,0.06); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
                    <div style="font-size: 12.5px; color: #cbd5e1;">
                        <strong>Thiết bị Master Admin gần nhất:</strong>
                        <span class="code-box"><?= htmlspecialchars((string)$masterInfo['hwid']) ?></span>
                        <span style="color:var(--text-muted); margin-left:6px;"><?= htmlspecialchars((string)($masterInfo['device_label'] ?? '')) ?> • <?= htmlspecialchars((string)($masterInfo['last_login'] ?? '')) ?></span>
                    </div>
                    <form method="POST" style="display:inline;" onsubmit="return confirm('Xóa liên kết HWID của Master Admin gốc?');">
                        <?= csrfField() ?>
                        <input type="hidden" name="action" value="reset_master_hwid">
                        <button type="submit" class="btn btn-sm" style="background: rgba(6,182,212,0.15); color: #22d3ee;"><i class="fa-solid fa-arrows-rotate"></i> Reset HWID Master</button>
                    </form>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- TAB 4: LOGS -->
        <div id="logsTab" class="tab-pane" style="display: none;">
            <div class="content-card">
                <div class="card-header">
                    <span class="card-title"><i class="fa-solid fa-history"></i> Nhật Ký Hoạt Động Gần Đây</span>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>THỜI GIAN</th>
                                <th>LOẠI</th>
                                <th>TÀI KHOẢN</th>
                                <th>NỘI DUNG</th>
                                <th>IP TRUY CẬP</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($allLogs)): ?>
                                <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">Chưa có nhật ký nào.</td></tr>
                            <?php else: foreach (array_slice(array_reverse($allLogs), 0, 80) as $l):
                                $logType = (string)($l['type'] ?? ($l['action'] ?? 'event'));
                                $logUser = (string)($l['username'] ?? ($l['key'] ?? ''));
                                $logMsg = (string)($l['message'] ?? ($l['details'] ?? ''));
                            ?>
                                <tr>
                                    <td style="font-size: 11.5px; color: var(--text-muted);"><?= htmlspecialchars((string)($l['time'] ?? '')) ?></td>
                                    <td>
                                        <?php if ($logType === 'login_success' || $logType === 'KEY_ACTIVATED'): ?>
                                            <span class="badge badge-active"><?= htmlspecialchars($logType) ?></span>
                                        <?php elseif (str_contains($logType, 'FAIL') || str_contains($logType, 'DENY') || str_contains($logType, 'TAMPER') || str_contains($logType, 'REPLAY')): ?>
                                            <span class="badge badge-blocked"><?= htmlspecialchars($logType) ?></span>
                                        <?php else: ?>
                                            <span class="badge badge-member"><?= htmlspecialchars($logType) ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><strong><?= htmlspecialchars($logUser) ?></strong></td>
                                    <td><?= htmlspecialchars($logMsg) ?></td>
                                    <td><span class="code-box"><?= htmlspecialchars((string)($l['ip'] ?? 'Unknown')) ?></span></td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        function filterKeys() {
            var query = (document.getElementById('searchKeyInput')?.value || '').trim().toLowerCase();
            var statusFilter = document.getElementById('filterKeyStatus')?.value || 'all';
            var durationFilter = document.getElementById('filterKeyDuration')?.value || 'all';
            var clearBtn = document.getElementById('clearSearchKeyBtn');

            if (clearBtn) {
                clearBtn.style.display = query ? 'block' : 'none';
            }

            var rows = document.querySelectorAll('#keysTableBody tr.key-row');
            var visibleCount = 0;

            rows.forEach(function(row) {
                var key = row.getAttribute('data-key') || '';
                var hwids = row.getAttribute('data-hwids') || '';
                var duration = row.getAttribute('data-duration') || '';
                var status = row.getAttribute('data-status') || '';
                var textContent = row.textContent.toLowerCase();

                var matchesQuery = !query || key.includes(query) || hwids.includes(query) || textContent.includes(query);
                var matchesStatus = (statusFilter === 'all') || (status === statusFilter);

                var matchesDuration = true;
                if (durationFilter !== 'all') {
                    if (durationFilter === 'permanent') {
                        matchesDuration = duration.includes('permanent') || duration.includes('vĩnh viễn') || key.includes('life');
                    } else if (durationFilter === '30d') {
                        matchesDuration = duration.includes('30') || key.includes('30d');
                    } else if (durationFilter === '7d') {
                        matchesDuration = duration.includes('7') || key.includes('7d');
                    } else if (durationFilter === '1d') {
                        matchesDuration = duration.includes('1d') || duration === '1' || key.includes('1d');
                    } else if (durationFilter === '1h') {
                        matchesDuration = duration.includes('1h') || key.includes('1h');
                    }
                }

                if (matchesQuery && matchesStatus && matchesDuration) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            var badge = document.getElementById('keyCountBadge');
            if (badge) {
                badge.textContent = visibleCount + ' / ' + rows.length + ' key';
            }

            var noMatchRow = document.getElementById('noKeyMatchRow');
            if (noMatchRow) {
                noMatchRow.style.display = (visibleCount === 0 && rows.length > 0) ? '' : 'none';
            }
        }

        function clearKeySearch() {
            var input = document.getElementById('searchKeyInput');
            if (input) {
                input.value = '';
                filterKeys();
                input.focus();
            }
        }

        function copyAllCreatedKeys() {
            var textarea = document.getElementById('allCreatedKeysTextarea');
            var btn = document.getElementById('copyAllKeysBtn');
            if (!textarea) return;

            textarea.select();
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(textarea.value).then(function() {
                    showCopiedFeedback(btn);
                }).catch(function() {
                    document.execCommand('copy');
                    showCopiedFeedback(btn);
                });
            } else {
                document.execCommand('copy');
                showCopiedFeedback(btn);
            }
        }

        function showCopiedFeedback(btn) {
            if (!btn) return;
            var origHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-check" style="color: #34d399;"></i> ĐÃ SAO CHÉP TẤT CẢ KEY!';
            btn.style.background = '#059669';
            setTimeout(function() {
                btn.innerHTML = origHtml;
                btn.style.background = 'linear-gradient(135deg, #9333ea, #06b6d4)';
            }, 2500);
        }

        function resetKeyFilters() {
            var searchInput = document.getElementById('searchKeyInput');
            var statusSelect = document.getElementById('filterKeyStatus');
            var durationSelect = document.getElementById('filterKeyDuration');
            if (searchInput) searchInput.value = '';
            if (statusSelect) statusSelect.value = 'all';
            if (durationSelect) durationSelect.value = 'all';
            filterKeys();
        }

        function promptBanReason(form, hwid) {
            var reason = prompt('BAN vĩnh viễn thiết bị HWID:\\n' + hwid + '\\n\\nNhập lý do khóa (để trống sẽ dùng mặc định):', 'Vi phạm điều khoản sử dụng');
            if (reason === null) {
                return false;
            }
            var input = form.querySelector('input[name="reason"]');
            if (input) {
                input.value = reason.trim();
            }
            return true;
        }

        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-pane').forEach(el => el.style.display = 'none');
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            var target = document.getElementById(tabId);
            if (target) target.style.display = 'block';
            if (btn) btn.classList.add('active');
            try {
                localStorage.setItem('admin_active_tab', tabId);
            } catch (e) {}
        }

        document.addEventListener('DOMContentLoaded', function() {
            // Chống F5 nạp lại dữ liệu form POST của trình duyệt
            if (window.history.replaceState) {
                window.history.replaceState(null, null, window.location.href);
            }

            var params = new URLSearchParams(window.location.search);
            var urlTab = params.get('tab');
            var savedTab = urlTab || localStorage.getItem('admin_active_tab') || 'keysTab';
            var tabBtn = document.querySelector('.tab-btn[onclick*="' + savedTab + '"]');
            if (tabBtn) {
                switchTab(savedTab, tabBtn);
            }

            // Kích hoạt bộ lọc tìm kiếm key nếu có sẵn query
            if (document.getElementById('searchKeyInput')?.value) {
                filterKeys();
            }
        });
    </script>
<?php endif; ?>

</body>
</html>
