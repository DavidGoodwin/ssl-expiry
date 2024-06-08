<?php

foreach(file(__DIR__ . '/hosts.conf') as $line) {
    if (preg_match('/^#/', $line)) {
        continue;
    }
    $details = _parse($line);
    #echo "Checking : " . json_encode($details).  "\n";
    $ok = _check($details['host_name'], $details['host_address'], $details['port']);
    if ($ok !== true) {
        echo "Warning: " . json_encode($details) . " expires on $ok\n";
    }
}

/**
 * parse a single line, default port to 443 (https) unless specified
 *
 * @param string line like 'hostname' or 'hostname:port' or hostname:port#ip.address
 * @return array{host_name: string, host_address: string, port: int}
 */
function _parse(string $line) : array {
    $line = trim($line);

    $host_address = null; // underlying ip address if we need to poke one (e.g. cloudflare is infront of a hostname)
    $port = 443;

    $bits = explode('#', $line);
    if(count($bits) == 2) {
        $host_address= $bits[1];
        $line = $bits[0]; // remove # bit
    }

    $host_name = $line; // default

    if (preg_match('/(.*):(\d+)/', $line, $matches)) {
        $host_name = $matches[1];
        $port = (int) $matches[2];
    }
    
    return ['host_name' => $host_name, 'host_address' => $host_address ?? $host_name, 'port' => $port];
}

/**
 * Check given host/port
 * @return boolean|string true if it expires more than 1 week away, otheriwse expiry date.
 */
function _check(string $host_name, string $host_address, int $port) {

    $tls_ports = [25 => 'smtp', 143 => 'imap', 21 => 'ftp'];
    $starttls = '';

    if (array_key_exists($port, $tls_ports)) {
        $starttls = " -starttls {$tls_ports[$port]} ";
    }

    /**
     * @psalm-suppress ForbiddenCode
     */
    $output = shell_exec("echo | openssl s_client -connect $host_address:$port -servername $host_name $starttls 2>/dev/null | openssl x509 -in /dev/stdin -noout -dates");
    if ($output !== null && preg_match('/notAfter=(.*)$/',$output, $matches)) {
        $date = new DateTime($matches[1]);
        if ($date > new DateTime('+1 weeks')) {
            return true;
        }
        return $date->format('Y-m-d');
    }
    return "Weird date line : $output ";
}
