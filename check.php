<?php

foreach(file('hosts.conf') as $line) {
    list($host, $port) = _parse($line);
    $ok = _check($host, $port);
    if($ok !== true) {
        echo "Warning: $host ($port) expires on $ok\n";
    }
}

/**
 * parse a single line, default port to 443 (https) unless specified
 *
 * @param string line like 'hostname' or 'hostname:port'
 * @return array ($host, $port)
 */
function _parse($line) {
    $line = trim($line);
    if(preg_match('/(.*):(\d+)/', $line, $matches)) {
        return array($matches[1], $matches[2]);
    }
    return array($line, '443');
}

/**
 * Check given host/port
 * @return boolean|string true if it expires more than 1 week away, otheriwse expiry date.
 */
function _check($host, $port) {
    $tls_ports = [25 => 'smtp', '143' => 'imap' ];
    $starttls = '';
    if(isset($tls_ports[$port])) {
        $starttls = " -starttls {$tls_ports[$port]} ";
    }
    $output = shell_exec("echo | openssl s_client -connect $host:$port -servername $host $starttls 2>/dev/null | openssl x509 -noout -dates");
    if(preg_match('/notAfter=(.*)$/',$output, $matches)) {
        $date = new DateTime($matches[1]);
        if($date > new DateTime('+1 weeks')) {
            return true;
        }
        return $date->format('Y-m-d');
    }
}
