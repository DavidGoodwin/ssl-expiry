<?php

foreach(file(__DIR__ . '/hosts.conf') as $line) {
    $line = trim($line);
    if (empty($line) || preg_match('/^#/', $line)) {
        continue;
    }
    $details = _parse($line);
    #echo "Checking : " . json_encode($details).  "\n";
    $ok = _check($details['host_name'], $details['host_address'], $details['port']);
    if ($ok !== true) {
        echo "Warning: " . json_encode($details) . ": $ok\n";
    }
}

/**
 * parse a single line, default port to 443 (https) unless specified
 *
 * @param string line like 'hostname' or 'hostname:port' or hostname:port#ip.address
 * @return array{host_name: string, host_address: string, port: int}
 */
function _parse(string $line) : array {

    $host_address = null; // underlying ip address if we need to poke one (e.g. cloudflare is infront of a hostname)
    $port = 443;

    $bits = explode('#', $line);
    if(count($bits) == 2) {
        $host_address= $bits[1];
        $line = $bits[0]; // remove # bit
    }

    $host_name = $line; // default

    if (preg_match('/^(.+):(\d+)$/', $line, $matches)) {
        $host_name = $matches[1];
        $port = (int) $matches[2];
    }
    
    return ['host_name' => $host_name, 'host_address' => $host_address ?? $host_name, 'port' => $port];
}

/**
 * Check given host/port.
 *
 * Returns true if the certificate is trusted and expires more than 1 week away,
 * otherwise a string describing the problem(s): an upcoming expiry date, a trust
 * failure (self-signed, untrusted root, hostname mismatch, expired), or both.
 *
 * @return boolean|string
 */
function _check(string $host_name, string $host_address, int $port) {

    $starttls_ports = [25 => 'smtp', 143 => 'imap'];

    // First try a verifying connection. If the chain/hostname check fails we still
    // want the expiry, so retry without verification and remember the trust error.
    $validity_error = null;
    $cert = _open($host_name, $host_address, $port, true, $starttls_ports, $err);
    if ($cert === null) {
        $validity_error = $err;
        $cert = _open($host_name, $host_address, $port, false, $starttls_ports, $err);
        if ($cert === null) {
            return "could not connect: $err"; // genuinely unreachable, not just untrusted
        }
    }

    $info = openssl_x509_parse($cert);
    if ($info === false || !isset($info['validTo_time_t'])) {
        return "could not parse certificate";
    }

    $problems = [];
    if ($validity_error !== null) {
        $problems[] = "invalid certificate ($validity_error)";
    }
    $date = (new DateTime())->setTimestamp($info['validTo_time_t']);
    if ($date <= new DateTime('+1 weeks')) {
        $problems[] = "expires " . $date->format('Y-m-d');
    }

    return $problems === [] ? true : implode('; ', $problems);
}

/**
 * Open a connection and return the peer certificate, or null on failure.
 *
 * When $verify is true the TLS stack validates the chain and hostname, so a null
 * return sets $error to the reason (e.g. "self signed certificate in certificate chain").
 *
 * @param array<int,string> $starttls_ports
 * @param-out string|null $error
 * @return \OpenSSLCertificate|resource|null
 */
function _open(string $host_name, string $host_address, int $port, bool $verify, array $starttls_ports, ?string &$error) {

    $error = null;

    $ctx = stream_context_create(['ssl' => [
        'capture_peer_cert' => true,
        'SNI_enabled'       => true,
        'peer_name'         => $host_name, // SNI / servername; may differ from the address we connect to
        'verify_peer'       => $verify,
        'verify_peer_name'  => $verify,
    ]]);

    // STARTTLS protocols start in plaintext and upgrade; everything else is TLS from the first byte.
    $scheme = isset($starttls_ports[$port]) ? 'tcp' : 'ssl';

    // Capture SSL warnings so we can report *why* verification failed.
    $warnings = '';
    set_error_handler(function (int $errno, string $errstr) use (&$warnings) : bool {
        $warnings .= $errstr . "\n";
        return true;
    });

    // echo | openssl s_client -connect $host_address:$port -servername $host_name $starttls 2>/dev/null | openssl x509 -in /dev/stdin -noout -dates
    try {
        $client = stream_socket_client(
            "{$scheme}://{$host_address}:{$port}",
            $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx
        );
        if ($client === false) {
            $error = _ssl_error($warnings !== '' ? $warnings : ($errstr !== '' ? $errstr : "error $errno"));
            return null;
        }
        stream_set_timeout($client, 10);

        if (isset($starttls_ports[$port])) {
            if (!_starttls($client, $starttls_ports[$port])) {
                fclose($client);
                $error = "STARTTLS negotiation failed";
                return null;
            }
            if (stream_socket_enable_crypto($client, true, STREAM_CRYPTO_METHOD_TLS_CLIENT) !== true) {
                fclose($client);
                $error = _ssl_error($warnings !== '' ? $warnings : "TLS handshake failed");
                return null;
            }
        }
    } finally {
        restore_error_handler();
    }

    $params = stream_context_get_params($client);
    fclose($client);

    return $params['options']['ssl']['peer_certificate'] ?? null;
}

/**
 * Boil an OpenSSL/stream warning down to a concise human reason.
 */
function _ssl_error(string $msg) : string {
    if (preg_match('/verify error:num=\d+:([^\r\n]+)/', $msg, $m)) {
        return trim($m[1]); // e.g. "self signed certificate in certificate chain"
    }
    if (stripos($msg, 'did not match') !== false) {
        return "hostname mismatch";
    }
    if (stripos($msg, 'certificate verify failed') !== false) {
        return "certificate verify failed";
    }
    // Otherwise tidy the raw stream warnings: drop the "function():" prefixes and
    // return the first informative line (e.g. "Connection reset by peer").
    foreach (preg_split('/[\r\n]+/', $msg) ?: [] as $line) {
        $line = trim((string) preg_replace('/^\s*\w+\(\):\s*/', '', $line));
        $line = (string) preg_replace('/^SSL:\s*/', '', $line);
        if ($line !== ''
            && stripos($line, 'Failed to enable crypto') === false
            && stripos($line, 'Unable to connect') === false) {
            return $line;
        }
    }
    return trim((string) preg_replace('/\s+/', ' ', $msg));
}

/**
 * Negotiate STARTTLS on an already-connected plaintext stream, leaving it ready
 * for stream_socket_enable_crypto().
 *
 * @param resource $client
 * @return bool true if the server agreed to upgrade
 */
function _starttls($client, string $protocol) : bool {

    // read one response, consuming multiline replies (e.g. SMTP "250-...") down to the final line
    $response = function () use ($client) : string {
        do {
            $line = (string) fgets($client, 1024);
        } while (preg_match('/^\d{3}-/', $line));
        return $line;
    };

    if ($protocol === 'smtp') {
        if (strpos($response(), '220') !== 0) {   // server greeting
            return false;
        }
        fwrite($client, "EHLO sslexpiry\r\n");
        if (strpos($response(), '250') !== 0) {   // EHLO accepted
            return false;
        }
        fwrite($client, "STARTTLS\r\n");
        return strpos($response(), '220') === 0;  // ready to start TLS
    }

    if ($protocol === 'imap') {
        $response();                              // "* OK ..." greeting
        fwrite($client, "a STARTTLS\r\n");
        return (bool) preg_match('/^a OK/i', $response());
    }

    return false;
}
