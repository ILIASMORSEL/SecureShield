<?php

use PHPUnit\Framework\TestCase;
use SecureShield\SecureShield;

class SecureShieldTest extends TestCase
{
    private $shield;

    protected function setUp(): void
    {
        $db = new PDO('sqlite::memory:');
        $this->shield = SecureShield::init($db, []);
    }

    public function testEscapeHTML()
    {
        $input = '<script>alert("XSS")</script>';
        $expected = '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;';
        $this->assertEquals($expected, $this->shield->escapeHTML($input));
    }

    public function testCSRFToken()
    {
        $token = $this->shield->generateCSRFToken();
        $this->assertTrue($this->shield->validateCSRFToken($token));
    }
}
