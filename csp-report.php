<?php
setlocale(LC_ALL, 'en_US.UTF8');
date_default_timezone_set('Europe/Berlin');

if ($_SERVER['CONTENT_TYPE'] !== 'application/csp-report') {
    http_response_code(400); // Bad Request
    exit("Invalid content type: ".$_SERVER['CONTENT_TYPE']);
}

$data = file_get_contents('php://input');

if ($data) {
    $obj = json_decode($data, true);
    if (json_last_error() === JSON_ERROR_NONE && isset($obj['csp-report'])) {
        $report = $obj['csp-report'];
        $fields = [
            "Document URI:\t\t" => "document-uri",
			"Status Code:\t\t" => "status-code",
			"Disposition:\t\t" => "disposition",
			"Effective Directive:\t" => "effective-directive",
            "Violated Directive:\t" => "violated-directive",
            "Original Policy:\t" => "original-policy",
            "Blocked URI:\t\t" => "blocked-uri",
			"Script Sample:\n" => "script-sample",
        ];

        $log = "\n===============" . date("j.n.Y H:i:s") . "===============\n";
        foreach ($fields as $label => $key) {
            if (isset($report[$key])) {
                $log .= "$label" . htmlspecialchars($report[$key]) . "\n";
            }
        }

        $logFile = 'csp-violations.log';
        file_put_contents($logFile, $log, FILE_APPEND | LOCK_EX);
    } else {
        http_response_code(400); // Bad Request
        exit("Invalid JSON payload.");
    }
} else {
    http_response_code(204); // No Content
    exit();
}
?>
