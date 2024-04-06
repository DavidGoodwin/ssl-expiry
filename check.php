<?php

foreach(file(__DIR__ . '/hosts.conf') as $line) {
    if (preg_match('/^#/', $line)) {
        continue;
    }
    list($host, $port) = _parse($line);
    //echo "Chekcing $host\n";
    $ok = _check($host, $port);
    if ($ok !== true) {
        echo "Warning: $host ($port) expires on $ok\n";
    }
}

/**
 * parse a single line, default port to 443 (https) unless specified
 *
 * @param string line like 'hostname' or 'hostname:port'
 * @return array ($host, $port)
 */
function _parse(string $line) : array {
    $line = trim($line);
    if (preg_match('/(.*):(\d+)/', $line, $matches)) {
        return array($matches[1], $matches[2]);
    }
    return array($line, '443');
}

/**
 * Check given host/port
 * @return boolean|string true if it expires more than 1 week away, otheriwse expiry date.
 */
function _check(string $host, string $port) {

    $port = (int) $port;

    $tls_ports = [25 => 'smtp', 143 => 'imap', 21 => 'ftp'];
    $starttls = '';

    if (array_key_exists($port, $tls_ports)) {
        $starttls = " -starttls {$tls_ports[$port]} ";
    }

    /**
     * @psalm-suppress ForbiddenCode
     */
    $output = shell_exec("echo | openssl s_client -connect $host:$port -servername $host $starttls 2>/dev/null | openssl x509 -in /dev/stdin -noout -dates");
    if ($output !== null && preg_match('/notAfter=(.*)$/',$output, $matches)) {
        $date = new DateTime($matches[1]);
        if ($date > new DateTime('+1 weeks')) {
            return true;
        }
        return $date->format('Y-m-d');
    }
    return "Weird date line : $output ";
}
