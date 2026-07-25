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
$cacheFile = __DIR__ . '/geo_cache.json';

// Load geo cache
$geoCache = [];
if (file_exists($cacheFile)) {
    $geoCache = json_decode(file_get_contents($cacheFile), true) ?: [];
}

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
$cityStats = [];
$stateStats = [];

$now = time();
$cutoff24h = $now - (24 * 3600);
$processedLines = [];

function detectDevice($ua) {
    $ua = strtolower($ua);
    if (preg_match('/bot|crawler|spider|scanner/i', $ua)) return 'Bot';
    if (preg_match('/ipad|tablet|silk|playbook/i', $ua)) return 'Tablet';
    if (preg_match('/android.*mobile|iphone|ipod|windows phone|blackberry|opera mini|mobile/i', $ua)) return 'Mobile';
    if (preg_match('/android(?!.*mobile)/i', $ua)) return 'Tablet';
    if (preg_match('/mobile|android|iphone|ipod|blackberry|opera mini|windows phone/i', $ua)) return 'Mobile';
    if (preg_match('/windows nt|macintosh|mac os x|linux|x11|cros/i', $ua)) return 'Desktop';
    return 'Unknown';
}

function detectOS($ua) {
    $ua = strtolower($ua);
    if (preg_match('/bot|crawler|spider/i', $ua)) return 'Bot';
    if (preg_match('/windows nt 10/i', $ua)) return 'Windows 10/11';
    if (preg_match('/windows nt 6\.3/i', $ua)) return 'Windows 8.1';
    if (preg_match('/windows nt 6\.1/i', $ua)) return 'Windows 7';
    if (preg_match('/windows/i', $ua)) return 'Windows';
    if (preg_match('/iphone/i', $ua)) return 'iOS';
    if (preg_match('/ipad/i', $ua)) return 'iPadOS';
    if (preg_match('/mac os x|macintosh/i', $ua)) return 'macOS';
    if (preg_match('/android/i', $ua)) return 'Android';
    if (preg_match('/linux/i', $ua) && !preg_match('/android/i', $ua)) return 'Linux';
    if (preg_match('/cros/i', $ua)) return 'ChromeOS';
    return 'Unknown';
}

// Collect all unique IPs that need geolocation
$ipsNeedingGeo = [];

foreach ($logFiles as $lf) {
    if (!file_exists($lf)) continue;
    $handle = @fopen($lf, 'r');
    if (!$handle) continue;
    while (($line = fgets($handle, 4096)) !== false) {
        $hash = md5($line);
        if (isset($processedLines[$hash])) continue;
        $processedLines[$hash] = true;

        if (!preg_match('/^([\d\.]+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"/', $line, $m)) continue;
        
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
        if (stripos($referer, 'blackday') !== false) $isBlackday = true;
        if ($path === '/' || $path === '/favicon.ico') $isBlackday = true;
        if (strpos($lf, 'blackday_access') !== false) $isBlackday = true;
        if (!$isBlackday) continue;
        
        $isBot = preg_match('/bot|crawler|spider|scanner|CMS-Checker|InternetMeasure/i', $ua);
        $isSecurityScan = preg_match('/\.env|\.git|wp-config|xmlrpc|wlwmanifest|sitemap|appsettings|render\.yaml|mcp\.json|nuxt\.config|vite\.config|env\.js|settings\.json|vercel\.json|actuator|signup|pricing|dashboard|settings|app/i', $path);
        if ($isSecurityScan) continue;
        
        $totalRequests++;
        $uniqueIPs[$ip] = ($uniqueIPs[$ip] ?? 0) + 1;
        
        // Track IPs needing geo lookup
        if (!isset($ipDetails[$ip]) && !isset($geoCache[$ip])) {
            $ipsNeedingGeo[$ip] = true;
        }
        
        $browser = 'Other';
        if (preg_match('/Edg/i', $ua)) $browser = 'Edge';
        elseif (preg_match('/Chrome/i', $ua)) $browser = 'Chrome';
        elseif (preg_match('/Firefox/i', $ua)) $browser = 'Firefox';
        elseif (preg_match('/Safari/i', $ua) && !preg_match('/Chrome/i', $ua)) $browser = 'Safari';
        if ($isBot) $browser = 'Bot';
        
        $device = detectDevice($ua);
        $os = detectOS($ua);
        
        $browserStats[$browser] = ($browserStats[$browser] ?? 0) + 1;
        $deviceStats[$device] = ($deviceStats[$device] ?? 0) + 1;
        $osStats[$os] = ($osStats[$os] ?? 0) + 1;
        
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
        
        if (count($ipDetails[$ip]['paths']) < 5 && !in_array($path, $ipDetails[$ip]['paths'])) {
            $ipDetails[$ip]['paths'][] = $path;
        }
        
        $pathStats[$path] = ($pathStats[$path] ?? 0) + 1;
        if ($timestamp >= $cutoff24h) $visitors24h++;
        
        $hour = date('d M H:00', $timestamp);
        $hourlyActivity[$hour] = ($hourlyActivity[$hour] ?? 0) + 1;
        $day = date('Y-m-d', $timestamp);
        $dailyActivity[$day] = ($dailyActivity[$day] ?? 0) + 1;
        
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
            ];
        }
    }
    fclose($handle);
}

// Batch geo-lookup for new IPs (max 100 per request, respect rate limit)
$ipsToLookup = array_keys($ipsNeedingGeo);
// Filter out private/local IPs
$ipsToLookup = array_filter($ipsToLookup, function($ip) {
    return !preg_match('/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/', $ip);
});

// Batch lookup in chunks of 100
$newGeoData = [];
$chunks = array_chunk($ipsToLookup, 100);
foreach ($chunks as $chunk) {
    if (count($chunk) == 0) break;
    $postData = json_encode(array_map(fn($ip) => ['query' => $ip], $chunk));
    $ch = curl_init('http://ip-api.com/batch?fields=query,country,regionName,city,isp,status');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $postData,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode === 200 && $response) {
        $results = json_decode($response, true);
        if (is_array($results)) {
            foreach ($results as $r) {
                if (isset($r['query']) && ($r['status'] ?? '') === 'success') {
                    $geoCache[$r['query']] = [
                        'city' => $r['city'] ?? 'Unknown',
                        'state' => $r['regionName'] ?? 'Unknown',
                        'country' => $r['country'] ?? 'Unknown',
                        'isp' => $r['isp'] ?? 'Unknown',
                    ];
                }
            }
        }
    }
    break; // Only process first chunk to respect rate limits (100 IPs/min)
}

// Save cache
file_put_contents($cacheFile, json_encode($geoCache, JSON_PRETTY_PRINT));

// Apply geo data and build location stats
foreach ($ipDetails as $ip => &$data) {
    $geo = $geoCache[$ip] ?? ['city' => 'Unknown', 'state' => 'Unknown', 'country' => 'Unknown', 'isp' => 'Unknown'];
    $data['city'] = $geo['city'];
    $data['state'] = $geo['state'];
    $data['country'] = $geo['country'];
    $data['isp'] = $geo['isp'];
    
    // Location stats
    $cityKey = $geo['city'] . ', ' . $geo['state'];
    $cityStats[$cityKey] = ($cityStats[$cityKey] ?? 0) + 1;
    $stateStats[$geo['state']] = ($stateStats[$geo['state']] ?? 0) + 1;
}

// Build location-based visitor list (no IPs exposed)
uasort($ipDetails, function($a, $b) { return $b['requests'] - $a['requests']; });

$topVisitors = [];
$count = 0;
$visitorNum = 0;
foreach ($ipDetails as $ip => $data) {
    if ($count >= 30) break;
    $visitorNum++;
    // Generate a visitor ID instead of showing IP
    $visitorId = 'V' . str_pad($visitorNum, 3, '0', STR_PAD_LEFT);
    $topVisitors[] = [
        'id' => $visitorId,
        'location' => $data['city'] . ', ' . $data['state'],
        'country' => $data['country'],
        'isp' => $data['isp'],
        'requests' => $data['requests'],
        'first' => date('d M H:i', $data['first']),
        'last' => date('d M H:i', $data['last']),
        'device' => $data['device'],
        'os' => $data['os'],
        'browser' => $data['browser'],
        'paths' => array_slice(array_values($data['paths']), 0, 4)
    ];
    $count++;
}

// Remove IPs from recent requests
foreach ($recentRequests as &$req) {
    $geo = $geoCache[$req['ip']] ?? ['city' => 'Unknown', 'state' => 'Unknown', 'isp' => 'Unknown'];
    $req['city'] = $geo['city'];
    $req['state'] = $geo['state'];
    $req['isp'] = $geo['isp'];
    unset($req['ip']); // Remove raw IP
}

// Sort
usort($recentRequests, function($a, $b) { return $b['timestamp'] - $a['timestamp']; });
arsort($pathStats);
arsort($browserStats);
arsort($deviceStats);
arsort($osStats);
arsort($cityStats);
arsort($stateStats);
ksort($dailyActivity);
ksort($hourlyActivity);

echo json_encode([
    'totalRequests' => $totalRequests,
    'uniqueVisitors' => count($uniqueIPs),
    'visitors24h' => $visitors24h,
    'dailyActivity' => array_slice($dailyActivity, -10, null, true),
    'hourlyActivity' => array_slice($hourlyActivity, -24, null, true),
    'topVisitors' => $topVisitors,
    'pathStats' => array_slice($pathStats, 0, 15, true),
    'browserStats' => $browserStats,
    'deviceStats' => $deviceStats,
    'osStats' => $osStats,
    'cityStats' => array_slice($cityStats, 0, 15, true),
    'stateStats' => array_slice($stateStats, 0, 10, true),
    'recentRequests' => array_slice($recentRequests, 0, 30),
    'geoCached' => count($geoCache),
    'generated' => date('Y-m-d H:i:s'),
    'timezone' => 'IST'
], JSON_PRETTY_PRINT);
