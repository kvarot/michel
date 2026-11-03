<?php
// Test page of the throwaway container, never of a real site: each kind provokes
// a real error, with what the request sends inside its message. The real run
// puts its markers there, then looks for them on the computer.
$m = (string) ($_GET['m'] ?? 'nobody');
$kind = (string) ($_GET['kind'] ?? 'php');
switch ($kind) {
    case 'db': // ERROR: the value is in the message, the query in STATEMENT.
        $c = pg_connect('dbname=postgres');
        @pg_query($c, "SELECT '" . pg_escape_string($c, $m) . "'::int");
        break;
    case 'db-fatal': // FATAL: the name is in the message.
        @pg_connect('dbname=' . preg_replace('/[^a-z0-9_]/', '_', strtolower($m)));
        break;
    case 'app': // A real Monolog line, as an application writes it.
        require '/usr/share/php/Monolog/autoload.php';
        $log = new Monolog\Logger('production');
        $log->pushHandler(new Monolog\Handler\StreamHandler('/var/www/app/storage/logs/app.log'));
        $log->critical('Payment failed for ' . $m, ['exception' => new RuntimeException('Card of ' . $m . ' refused')]);
        break;
    case 'warning':
        trigger_error('Odd value ' . $m, E_USER_WARNING);
        break;
    default: // A fatal error of PHP.
        throw new RuntimeException('failed for ' . $m);
}
echo "done\n";
