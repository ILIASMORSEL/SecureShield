<?php

namespace SecureShield;

class SecureShield
{
    private $db;
    private $config;
    private static $instance;

    public static function init($db = null, $config = [])
    {
        if (!self::$instance) {
            self::$instance = new self($db, $config);
        }
        return self::$instance;
    }

    private function __construct($db = null, $config = [])
    {
        $this->db = $db;
        $this->config = array_merge([
            'csrf_token_lifetime' => 3600,
            'allowed_redirect_hosts' => [],
            'log_file' => 'secure_shield.log',
            'strict_mode' => true,
            'session_fixation' => true,
            'rate_limit' => [
                'enabled' => true,
                'requests_per_minute' => 60,
                'ban_duration' => 3600, // Ban duration in seconds
            ],
            'firewall' => [
                'block_user_agents' => [
                    'sqlmap', 'curl', 'bot', 'crawler', 'python-requests'
                ],
                'block_ips' => [],
                'allow_only_ips' => [], // If not empty, only these IPs are allowed
            ]
        ], $config);

        if ($this->config['strict_mode']) {
            ini_set('session.cookie_httponly', 1);
            ini_set('session.cookie_secure', 1);
            ini_set('session.use_strict_mode', 1);
            error_reporting(E_ALL & ~E_NOTICE);
        }

        if ($this->config['session_fixation']) {
            $this->regenerateSession();
        }

        $this->applyFirewallRules();
    }

    /**
     * === Firewall ===
     */
    private function applyFirewallRules()
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

        if (!empty($this->config['firewall']['allow_only_ips']) && !in_array($ip, $this->config['firewall']['allow_only_ips'])) {
            $this->blockAccess("Access denied: IP not allowed.");
        }

        if (in_array($ip, $this->config['firewall']['block_ips'])) {
            $this->blockAccess("Access denied: IP blocked.");
        }

        foreach ($this->config['firewall']['block_user_agents'] as $blockedAgent) {
            if (stripos($userAgent, $blockedAgent) !== false) {
                $this->blockAccess("Access denied: User-Agent blocked.");
            }
        }
    }

    private function blockAccess($reason)
    {
        http_response_code(403);
        echo $this->escapeHTML("Forbidden: $reason");
        exit;
    }

    /**
     * === Rate Limiting ===
     */
    public function rateLimit()
    {
        if (!$this->config['rate_limit']['enabled']) {
            return;
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $time = time();
        $limit = $this->config['rate_limit']['requests_per_minute'];
        $banDuration = $this->config['rate_limit']['ban_duration'];

        $rateData = apcu_fetch("rate_limit_$ip");
        if ($rateData === false) {
            $rateData = ['count' => 0, 'start' => $time];
        }

        if ($rateData['count'] >= $limit) {
            if ($time - $rateData['start'] < 60) {
                apcu_store("ban_$ip", $time + $banDuration, $banDuration);
                $this->blockAccess("Rate limit exceeded. Try again later.");
            } else {
                $rateData = ['count' => 0, 'start' => $time];
            }
        }

        $rateData['count']++;
        apcu_store("rate_limit_$ip", $rateData, 60);
    }

    public function isIPBanned($ip)
    {
        $banEnd = apcu_fetch("ban_$ip");
        return $banEnd !== false && time() < $banEnd;
    }

    /**
     * === SQL Injection Protection ===
     */
    public function dbQuery($query, $params = [])
    {
        if (!$this->db) {
            throw new \Exception("Database connection not initialized.");
        }
        $stmt = $this->db->prepare($query);
        foreach ($params as $key => $value) {
            $stmt->bindValue(is_int($key) ? $key + 1 : ":$key", $value, $this->detectParamType($value));
        }
        $stmt->execute();
        return $stmt;
    }

    private function detectParamType($value)
    {
        if (is_int($value)) {
            return \PDO::PARAM_INT;
        } elseif (is_bool($value)) {
            return \PDO::PARAM_BOOL;
        } elseif (is_null($value)) {
            return \PDO::PARAM_NULL;
        } else {
            return \PDO::PARAM_STR;
        }
    }

    /**
     * === XSS Protection ===
     */
    public function escapeHTML($data)
    {
        return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * === CSRF Protection ===
     */
    public function generateCSRFToken()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = [
            'value' => $token,
            'expires_at' => time() + $this->config['csrf_token_lifetime']
        ];
        return $token;
    }

    public function validateCSRFToken($token)
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        if (empty($_SESSION['csrf_token']) || time() > $_SESSION['csrf_token']['expires_at']) {
            throw new \Exception("CSRF token expired or missing.");
        }
        return hash_equals($_SESSION['csrf_token']['value'], $token);
    }

    /**
     * === Session Fixation Protection ===
     */
    public function regenerateSession()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        session_regenerate_id(true);
    }

    /**
     * === Logging ===
     */
    public function log($message, $context = [])
    {
        $contextString = json_encode($context);
        file_put_contents(
            $this->config['log_file'],
            "[" . date('Y-m-d H:i:s') . "] $message | Context: $contextString\n",
            FILE_APPEND
        );
    }
}
