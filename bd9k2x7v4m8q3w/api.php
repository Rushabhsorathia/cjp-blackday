<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$logFiles = [
    '/var/log/nginx/blackday_access.log',
    '/var/log/nginx/blackday_access.log.1',
    '/var/log/nginx/access.log',
    '/var/log/nginx/access.log.1',
];

$blackdayPaths = ['narration.mp3', 'bd9k2x7v4m8q3w', 'INDIA-DARK', 'india-2014', 'favicon.ico', 'index.html'];

$totalRequests = 0;
$uniqueIPs = [];
$visitors24h = 0;
$hourlyActivity = [];
$dailyActivity = [];
$recentRequests = [];
$ipDetails = [];
$pathStats = [];
$browserStats = [];
$deviceStats = [];
$osStats = [];
$ispStats = [];
$countryStats = [];

$now = time();
$cutoff24h = $now - (24 * 3600);
$processedLines = [];

// Indian ISP IP ranges (simplified - first octet based)
$ispMap = [
    // Jio
    '49.36' => 'Jio', '49.37' => 'Jio', '49.38' => 'Jio', '49.39' => 'Jio',
    '49.40' => 'Jio', '49.41' => 'Jio', '49.42' => 'Jio', '49.43' => 'Jio',
    '49.44' => 'Jio', '49.45' => 'Jio', '49.46' => 'Jio', '49.47' => 'Jio',
    '157.32' => 'Jio', '157.33' => 'Jio', '157.34' => 'Jio', '157.35' => 'Jio',
    '47.11' => 'Jio', '47.29' => 'Jio', '47.30' => 'Jio', '47.31' => 'Jio',
    '47.8' => 'Jio', '47.9' => 'Jio', '47.10' => 'Jio',
    // Airtel
    '122.170' => 'Airtel', '122.171' => 'Airtel', '122.172' => 'Airtel', '122.173' => 'Airtel',
    '122.174' => 'Airtel', '122.175' => 'Airtel', '122.176' => 'Airtel', '122.177' => 'Airtel',
    '122.178' => 'Airtel', '122.179' => 'Airtel', '122.180' => 'Airtel', '122.181' => 'Airtel',
    '122.182' => 'Airtel', '122.183' => 'Airtel',
    // Vi/Vodafone
    '106.193' => 'Vi', '106.194' => 'Vi', '106.195' => 'Vi', '106.196' => 'Vi',
    '106.197' => 'Vi', '106.198' => 'Vi', '106.199' => 'Vi', '106.200' => 'Vi',
    '106.201' => 'Vi', '106.202' => 'Vi', '106.203' => 'Vi', '106.204' => 'Vi',
    '106.205' => 'Vi', '106.206' => 'Vi', '106.207' => 'Vi', '106.208' => 'Vi',
    '106.209' => 'Vi', '106.210' => 'Vi', '106.211' => 'Vi', '106.212' => 'Vi',
    '106.213' => 'Vi', '106.214' => 'Vi', '106.215' => 'Vi', '106.216' => 'Vi',
    '106.217' => 'Vi', '106.218' => 'Vi', '106.219' => 'Vi', '106.220' => 'Vi',
    '106.221' => 'Vi', '106.222' => 'Vi', '106.223' => 'Vi',
    // BSNL
    '117.194' => 'BSNL', '117.195' => 'BSNL', '117.196' => 'BSNL', '117.197' => 'BSNL',
    '117.198' => 'BSNL', '117.199' => 'BSNL', '117.200' => 'BSNL', '117.201' => 'BSNL',
    // ACT
    '183.82' => 'ACT', '183.83' => 'ACT',
    // Spectra/Tata
    '27.56' => 'Spectra', '27.57' => 'Spectra', '27.58' => 'Spectra', '27.59' => 'Spectra',
    '27.60' => 'Spectra', '27.61' => 'Spectra', '27.62' => 'Spectra',
    // Hathway
    '49.205' => 'Hathway', '49.206' => 'Hathway',
    // Excitel
    '103.87' => 'Excitel',
    // Tikona
    '113.193' => 'Tikona', '113.194' => 'Tikona',
    // You Broadband
    '203.192' => 'You Broadband', '203.193' => 'You Broadband',
    // BSNL mobile
    '111.92' => 'BSNL', '111.93' => 'BSNL', '111.94' => 'BSNL', '111.95' => 'BSNL',
    // Airtel mobile
    '223.176' => 'Airtel', '223.177' => 'Airtel', '223.178' => 'Airtel', '223.179' => 'Airtel',
    '223.180' => 'Airtel', '223.181' => 'Airtel', '223.182' => 'Airtel', '223.183' => 'Airtel',
    '223.184' => 'Airtel', '223.185' => 'Airtel', '223.186' => 'Airtel', '223.187' => 'Airtel',
    '223.188' => 'Airtel', '223.189' => 'Airtel', '223.190' => 'Airtel', '223.191' => 'Airtel',
    '223.228' => 'Airtel', '223.229' => 'Airtel',
];

function detectISP($ip, &$ispMap) {
    $parts = explode('.', $ip);
    if (count($parts) < 4) return 'Unknown';
    // Try 3-octet match first
    $key3 = $parts[0] . '.' . $parts[1] . '.' . $parts[2];
    if (isset($ispMap[$key3])) return $ispMap[$key3];
    // Try 2-octet
    $key2 = $parts[0] . '.' . $parts[1];
    if (isset($ispMap[$key2])) return $ispMap[$key2];
    // Cloud provider ranges
    $cloudRanges = ['34.', '35.', '52.', '54.', '104.22', '104.23', '172.7', '173.25', '164.9', '217.1', '87.2', '195.1', '107.1'];
    foreach ($cloudRanges as $cr) {
        if (strpos($ip, $cr) === 0) return 'Cloud/VPS';
    }
    // Indian ranges (rough)
    $indianFirstOctets = ['49', '59', '103', '106', '111', '117', '122', '125', '150', '152', '157', '171', '175', '182', '183', '202', '203', '210', '218', '223', '226', '227', '27', '42', '47', '27', '150', '152'];
    if (in_array($parts[0], $indianFirstOctets)) return 'Indian ISP';
    return 'International';
}

function detectDevice($ua) {
    $ua = strtolower($ua);
    if (preg_match('/bot|crawler|spider|scanner/i', $ua)) return 'Bot';
    // Tablet
    if (preg_match('/ipad|tablet|silk|playbook/i', $ua)) return 'Tablet';
    // Mobile
    if (preg_match('/android.*mobile|iphone|ipod|windows phone|blackberry|opera mini|mobile/i', $ua)) return 'Mobile';
    if (preg_match('/android(?!.*mobile)/i', $ua)) return 'Tablet';
    if (preg_match('/mobile|android|iphone|ipod|blackberry|opera mini|windows phone/i', $ua)) return 'Mobile';
    // Desktop
    if (preg_match('/windows nt|macintosh|mac os x|linux|x11|cros/i', $ua)) return 'Desktop';
    return 'Unknown';
}

function detectOS($ua) {
    $ua = strtolower($ua);
    if (preg_match('/bot|crawler|spider/i', $ua)) return 'Bot';
    // Windows
    if (preg_match('/windows nt 10/i', $ua)) return 'Windows 10/11';
    if (preg_match('/windows nt 6\.3/i', $ua)) return 'Windows 8.1';
    if (preg_match('/windows nt 6\.1/i', $ua)) return 'Windows 7';
    if (preg_match('/windows/i', $ua)) return 'Windows';
    // macOS
    if (preg_match('/mac os x|macintosh/i', $ua)) {
        if (preg_match('/iphone/i', $ua)) return 'iOS';
        if (preg_match('/ipad/i', $ua)) return 'iPadOS';
        return 'macOS';
    }
    if (preg_match('/iphone/i', $ua)) return 'iOS';
    if (preg_match('/ipad/i', $ua)) return 'iPadOS';
    if (preg_match('/ipod/i', $ua)) return 'iOS';
    // Android
    if (preg_match('/android/i', $ua)) return 'Android';
    // Linux
    if (preg_match('/linux/i', $ua) && !preg_match('/android/i', $ua)) return 'Linux';
    if (preg_match('/cros/i', $ua)) return 'ChromeOS';
    return 'Unknown';
}

foreach ($logFiles as $lf) {
    if (!file_exists($lf)) continue;
    $handle = @fopen($lf, 'r');
    if (!$handle) continue;
    while (($line = fgets($handle, 4096)) !== false) {
        $hash = md5($line);
        if (isset($processedLines[$hash])) continue;
        $processedLines[$hash] = true;

        if (!preg_match('/^([\d\.]+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"/', $line, $m)) {
            continue;
        }
        
        $ip = $m[1];
        $dateStr = $m[2];
        $request = $m[3];
        $status = $m[4];
        $size = $m[5];
        $referer = $m[6];
        $ua = $m[7];
        
        $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $dateStr);
        if (!$dt) continue;
        $timestamp = $dt->getTimestamp();
        
        $requestParts = explode(' ', $request);
        $method = $requestParts[0] ?? '';
        $path = $requestParts[1] ?? '';
        
        $isBlackday = false;
        foreach ($blackdayPaths as $bp) {
            if (stripos($path, $bp) !== false) { $isBlackday = true; break; }
        }
        if (stripos($referer, 'blackday') !== false) { $isBlackday = true; }
        if ($path === '/' || $path === '/favicon.ico') { $isBlackday = true; }
        if (strpos($lf, 'blackday_access') !== false) { $isBlackday = true; }
        if (!$isBlackday) continue;
        
        $isBot = preg_match('/bot|crawler|spider|scanner|CMS-Checker|InternetMeasure/i', $ua);
        $isSecurityScan = preg_match('/\.env|\.git|wp-config|xmlrpc|wlwmanifest|sitemap|appsettings|render\.yaml|mcp\.json|nuxt\.config|vite\.config|env\.js|settings\.json|vercel\.json|actuator|signup|pricing|dashboard|settings|app/i', $path);
        if ($isSecurityScan) continue;
        
        $totalRequests++;
        $uniqueIPs[$ip] = ($uniqueIPs[$ip] ?? 0) + 1;
        
        // Detect browser, device, OS, ISP
        $browser = 'Other';
        if (preg_match('/Edg/i', $ua)) $browser = 'Edge';
        elseif (preg_match('/Chrome/i', $ua)) $browser = 'Chrome';
        elseif (preg_match('/Firefox/i', $ua)) $browser = 'Firefox';
        elseif (preg_match('/Safari/i', $ua) && !preg_match('/Chrome/i', $ua)) $browser = 'Safari';
        if ($isBot) $browser = 'Bot';
        
        $device = detectDevice($ua);
        $os = detectOS($ua);
        $isp = detectISP($ip, $ispMap);
        
        // Stats
        $browserStats[$browser] = ($browserStats[$browser] ?? 0) + 1;
        $deviceStats[$device] = ($deviceStats[$device] ?? 0) + 1;
        $osStats[$os] = ($osStats[$os] ?? 0) + 1;
        $ispStats[$isp] = ($ispStats[$isp] ?? 0) + 1;
        
        // Determine country
        $country = 'India';
        $nonIndian = ['34', '35', '52', '104', '107', '136', '164', '172', '173', '195', '217', '87', '142', '217', '138', '165', '202'];
        $parts = explode('.', $ip);
        if (in_array($parts[0] ?? '', $nonIndian)) {
            $country = 'International';
        }
        $countryStats[$country] = ($countryStats[$country] ?? 0) + 1;
        
        if (!isset($ipDetails[$ip])) {
            $ipDetails[$ip] = [
                'ip' => $ip,
                'requests' => 0,
                'first' => $timestamp,
                'last' => $timestamp,
                'paths' => [],
                'browser' => $browser,
                'device' => $device,
                'os' => $os,
                'isp' => $isp,
                'country' => $country
            ];
        }
        $ipDetails[$ip]['requests']++;
        $ipDetails[$ip]['last'] = max($ipDetails[$ip]['last'], $timestamp);
        $ipDetails[$ip]['first'] = min($ipDetails[$ip]['first'], $timestamp);
        if (!$isBot) {
            $ipDetails[$ip]['browser'] = $browser;
            $ipDetails[$ip]['device'] = $device;
            $ipDetails[$ip]['os'] = $os;
        }
        
        if (count($ipDetails[$ip]['paths']) < 6 && !in_array($path, $ipDetails[$ip]['paths'])) {
            $ipDetails[$ip]['paths'][] = $path;
        }
        
        if (!isset($pathStats[$path])) $pathStats[$path] = 0;
        $pathStats[$path]++;
        
        if ($timestamp >= $cutoff24h) $visitors24h++;
        
        $hour = date('d M H:00', $timestamp);
        if (!isset($hourlyActivity[$hour])) $hourlyActivity[$hour] = 0;
        $hourlyActivity[$hour]++;
        
        $day = date('Y-m-d', $timestamp);
        if (!isset($dailyActivity[$day])) $dailyActivity[$day] = 0;
        $dailyActivity[$day]++;
        
        if (count($recentRequests) < 50) {
            $recentRequests[] = [
                'time' => $dt->format('d M H:i'),
                'timestamp' => $timestamp,
                'ip' => $ip,
                'path' => $path,
                'status' => $status,
                'browser' => $browser,
                'device' => $device,
                'os' => $os,
                'method' => $method
            ];
        }
    }
    fclose($handle);
}

uasort($ipDetails, function($a, $b) { return $b['requests'] - $a['requests']; });
usort($recentRequests, function($a, $b) { return $b['timestamp'] - $a['timestamp']; });
arsort($pathStats);
arsort($browserStats);
arsort($deviceStats);
arsort($osStats);
arsort($ispStats);
arsort($countryStats);
ksort($dailyActivity);
ksort($hourlyActivity);

$topIPs = [];
$count = 0;
foreach ($ipDetails as $ip => $data) {
    if ($count >= 30) break;
    $topIPs[] = [
        'ip' => $data['ip'],
        'requests' => $data['requests'],
        'first' => date('d M H:i', $data['first']),
        'last' => date('d M H:i', $data['last']),
        'browser' => $data['browser'],
        'device' => $data['device'],
        'os' => $data['os'],
        'isp' => $data['isp'],
        'country' => $data['country'],
        'paths' => array_slice(array_values($data['paths']), 0, 5)
    ];
    $count++;
}

echo json_encode([
    'totalRequests' => $totalRequests,
    'uniqueVisitors' => count($uniqueIPs),
    'visitors24h' => $visitors24h,
    'dailyActivity' => array_slice($dailyActivity, -10, null, true),
    'hourlyActivity' => array_slice($hourlyActivity, -24, null, true),
    'topIPs' => $topIPs,
    'pathStats' => array_slice($pathStats, 0, 15, true),
    'browserStats' => $browserStats,
    'deviceStats' => $deviceStats,
    'osStats' => $osStats,
    'ispStats' => $ispStats,
    'countryStats' => $countryStats,
    'recentRequests' => array_slice($recentRequests, 0, 30),
    'generated' => date('Y-m-d H:i:s'),
    'timezone' => 'IST'
], JSON_PRETTY_PRINT);
