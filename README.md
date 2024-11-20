# SecureShield 🛡️

**SecureShield** — это мощная библиотека безопасности для PHP, созданная для защиты вашего приложения от большинства известных атак, таких как **SQL-инъекции**, **XSS**, **CSRF**, **Command Injection**, **PHP Injection** и многих других.

Эта библиотека предлагает готовую защиту "из коробки" и лёгкую интеграцию в любой PHP-проект. Независимо от того, работаете ли вы над небольшим проектом или крупным веб-приложением, SecureShield станет вашим надежным щитом от атак.

---

## 🔥 **Особенности**

- ✅ **SQL Injection Protection** — безопасные SQL-запросы с использованием PDO и подготовленных выражений.
- ✅ **XSS Protection** — защита от внедрения вредоносного JavaScript через пользовательские данные.
- ✅ **CSRF Protection** — автоматическая генерация и проверка CSRF-токенов.
- ✅ **Command Injection Protection** — безопасное выполнение системных команд.
- ✅ **LDAP Injection Protection** — предотвращение атак на LDAP-запросы.
- ✅ **Open Redirect Protection** — проверка перенаправлений и защита от фишинговых атак.
- ✅ **Session Fixation Protection** — регулярное обновление идентификатора сессии для предотвращения фиксации.
- ✅ **Firewall** — блокировка IP-адресов и вредоносных User-Agent'ов.
- ✅ **Rate Limiting** — ограничение количества запросов для защиты от DoS-атак.
- ✅ **Гибкость** — настройка параметров под любой проект.
- ✅ **Лёгкость в использовании** — удобный API, который сразу готов к работе.

---

## 📦 **Установка**

### Через Composer (рекомендуется)
Для установки через Composer выполните команду:

```bash
composer require ILIASMORSEL/secure-shield
```


## 📦 **Ручная установка**

Скачайте библиотеку с GitHub.
Скопируйте файл src/SecureShield.php в ваш проект.
Подключите файл в своём коде:

```bash
require_once 'path/to/SecureShield.php';
```

## 🚀 **Быстрый старт**

Вот пример использования SecureShield:

```bash
use SecureShield\SecureShield;


// Подключение к базе данных
$db = new PDO('mysql:host=localhost;dbname=test', 'root', 'password');

// Настройка библиотеки
$config = [
    'csrf_token_lifetime' => 3600, // Время жизни CSRF-токена
    'allowed_redirect_hosts' => ['trusted.com', 'example.com'], // Разрешённые домены для редиректов
    'rate_limit' => [
        'enabled' => true,
        'requests_per_minute' => 100, // Лимит запросов в минуту
    ],
];

// Инициализация библиотеки
$shield = SecureShield::init($db, $config);

// SQL-инъекция: безопасный запрос
$query = "SELECT * FROM users WHERE username = :username";
$params = ['username' => $_POST['username']];
$result = $shield->dbQuery($query, $params)->fetchAll();

// Защита от XSS
echo $shield->escapeHTML('<script>alert("XSS!")</script>');

// CSRF: Генерация токена
$csrfToken = $shield->generateCSRFToken();
if ($_POST) {
    $shield->validateCSRFToken($_POST['csrf_token']); // Проверка токена
}

// Защита от Open Redirect
$safeUrl = $shield->validateRedirect('https://trusted.com/page');
```

## 🛡️ **Возможности**

### SQL Injection Protection

```bash
$query = "SELECT * FROM users WHERE email = :email";
$params = ['email' => $_POST['email']];
$result = $shield->dbQuery($query, $params)->fetchAll();
```

Защищает от SQL-инъекций через подготовленные выражения.
Все данные автоматически экранируются перед отправкой в базу.

### XSS Protection

```bash
echo $shield->escapeHTML('<script>alert("XSS!")</script>');
```

Превращает опасные символы (<, >, ", ') в безопасные HTML-эквиваленты.
Защита от выполнения вредоносного JavaScript.

### CSRF Protection

```bash
$csrfToken = $shield->generateCSRFToken();
if ($_POST) {
    $shield->validateCSRFToken($_POST['csrf_token']);
}
```

Генерация и проверка CSRF-токенов для защиты форм от подделки.

### Command Injection Protection

```bash
$command = $shield->sanitizeCommand('ls');
exec($command);
```

### Open Redirect Protection

```bash
$safeUrl = $shield->validateRedirect('https://trusted.com/page');
```

## 🛠️ **Настройка**

### Пример конфигурации:

```bash
$config = [
    'csrf_token_lifetime' => 3600,
    'allowed_redirect_hosts' => ['trusted.com', 'example.com'],
    'rate_limit' => [
        'enabled' => true,
        'requests_per_minute' => 100,
    ],
    'firewall' => [
        'block_user_agents' => ['sqlmap', 'curl', 'bot'], // Блокируем подозрительные User-Agent'ы
        'block_ips' => ['192.168.1.100'], // Блокируем определённые IP
    ],
];
```

## 📂 **Структура проекта**

```bash
SecureShield/
├── examples/                # Примеры использования
│   ├── basic-usage.php
│   └── advanced-usage.php
├── src/                     # Исходный код библиотеки
│   └── SecureShield.php
├── tests/                   # Юнит-тесты
│   └── SecureShieldTest.php
├── README.md                # Документация
├── CHANGELOG.md             # История изменений
├── LICENSE                  # Лицензия
├── composer.json            # Конфигурация для Composer
└── .gitignore               # Файлы, игнорируемые Git
```

## 📜 Лицензия

SecureShield распространяется под лицензией MIT License.

## 🚀 Планы на будущее

Добавить защиту от XXE (XML External Entities).
Добавить интеграцию с популярными фреймворками (Laravel, Symfony).
Улучшить документацию и добавить больше примеров.

## 🤝 **Вклад в проект**

Мы открыты к предложениям и улучшениям! Если вы нашли баг или хотите предложить улучшение, создайте issue или сделайте pull request. Мы всегда рады вашему участию! ❤️

Если вам нравится этот проект, вы можете поддержать его через Ko-fi:

[![Support me on Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/iliasmorsel)

 
