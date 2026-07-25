<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// Read from both the dedicated blackday log AND the global nginx log
// Global log has historical data before dedicated log was set up
$logFiles = [
    '/var/log/nginx/blackday_access.log',
    '/var/log/nginx/blackday_access.log.1',
    '/var/log/nginx/access.log',
    '/var/log/nginx/access.log.1',
];

// Known blackday paths to filter from global log
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

$now = time();
$cutoff24h = $now - (24 * 3600);
$processedLines = [];

foreach ($logFiles as $lf) {
    if (!file_exists($lf)) continue;
    $handle = @fopen($lf, 'r');
    if (!$handle) continue;
    while (($line = fgets($handle, 4096)) !== false) {
        // Deduplicate by line content hash
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
        
        // Skip non-blackday requests from global logs
        // Only count if path matches blackday patterns OR referer contains blackday
        $isBlackday = false;
        foreach ($blackdayPaths as $bp) {
            if (stripos($path, $bp) !== false) { $isBlackday = true; break; }
        }
        if (stripos($referer, 'blackday') !== false) { $isBlackday = true; }
        if ($path === '/' || $path === '/favicon.ico') { $isBlackday = true; } // root hits on blackday domain
        
        // For dedicated log, all entries are blackday
        if (strpos($lf, 'blackday_access') !== false) {
            $isBlackday = true;
        }
        
        if (!$isBlackday) continue;
        
        $isBot = preg_match('/bot|crawler|spider|scanner|CMS-Checker|InternetMeasure/i', $ua);
        $isSecurityScan = preg_match('/\.env|\.git|wp-config|xmlrpc|wlwmanifest|sitemap|appsettings|render\.yaml|mcp\.json|nuxt\.config|vite\.config|env\.js|settings\.json|vercel\.json|actuator|signup|pricing|dashboard|settings|app/i', $path);
        
        if ($isSecurityScan) continue;
        
        $totalRequests++;
        
        if (!isset($uniqueIPs[$ip])) {
            $uniqueIPs[$ip] = 0;
        }
        $uniqueIPs[$ip]++;
        
        if (!isset($ipDetails[$ip])) {
            $ipDetails[$ip] = [
                'ip' => $ip,
                'requests' => 0,
                'first' => $timestamp,
                'last' => $timestamp,
                'paths' => [],
                'browser' => 'Unknown'
            ];
        }
        $ipDetails[$ip]['requests']++;
        $ipDetails[$ip]['last'] = max($ipDetails[$ip]['last'], $timestamp);
        $ipDetails[$ip]['first'] = min($ipDetails[$ip]['first'], $timestamp);
        
        $cleanPath = $path;
        if ($ipDetails[$ip]['browser'] === 'Unknown' || !$isBot) {
            $browser = 'Other';
            if (preg_match('/Edg/i', $ua)) $browser = 'Edge';
            elseif (preg_match('/Chrome/i', $ua)) $browser = 'Chrome';
            elseif (preg_match('/Firefox/i', $ua)) $browser = 'Firefox';
            elseif (preg_match('/Safari/i', $ua) && !preg_match('/Chrome/i', $ua)) $browser = 'Safari';
            if ($isBot) $browser = 'Bot';
            if (!$isBot) $ipDetails[$ip]['browser'] = $browser;
            if (isset($browserStats[$browser])) $browserStats[$browser]++;
            else $browserStats[$browser] = 1;
        }
        
        if (count($ipDetails[$ip]['paths']) < 6 && !in_array($cleanPath, $ipDetails[$ip]['paths'])) {
            $ipDetails[$ip]['paths'][] = $cleanPath;
        }
        
        if (!isset($pathStats[$cleanPath])) $pathStats[$cleanPath] = 0;
        $pathStats[$cleanPath]++;
        
        if ($timestamp >= $cutoff24h) {
            $visitors24h++;
        }
        
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
                'path' => $cleanPath,
                'status' => $status,
                'browser' => $browser ?? 'Other',
                'method' => $method
            ];
        }
    }
    fclose($handle);
}

uasort($ipDetails, function($a, $b) { return $b['requests'] - $a['requests']; });
usort($recentRequests, function($a, $b) { return $b['timestamp'] - $a['timestamp']; });
arsort($pathStats);
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
    'recentRequests' => array_slice($recentRequests, 0, 30),
    'generated' => date('Y-m-d H:i:s'),
    'timezone' => 'IST'
], JSON_PRETTY_PRINT);
