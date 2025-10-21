🛡️ Bug Bounty Automation Setup

Автоматический скрипт для настройки полноценного окружения Bug Bounty с установкой популярных инструментов пентеста.
📋 Оглавление

    Описание

    Возможности

    Установка

    Структура проекта

    Установленные инструменты

    Использование

    Разработчик

🚀 Описание

Этот Python-скрипт автоматизирует процесс настройки окружения для Bug Bounty и пентестинга. Он создает организованную структуру папок и устанавливает более 20 популярных инструментов безопасности, сгруппированных по категориям уязвимостей.
✨ Возможности

    ✅ Автоматическая установка зависимостей системы

    ✅ Создание структурированных папок по типам уязвимостей

    ✅ Установка виртуального окружения Python для изоляции инструментов

    ✅ Массовая установка инструментов из GitHub репозиториев

    ✅ Поддержка multiple package managers (apt, dnf, yum)

    ✅ Кросс-дистрибутивная совместимость (Ubuntu, Fedora, CentOS)

    ✅ Обработка ошибок с подробным логированием

🛠️ Установка
Предварительные требования

    Linux-система (Ubuntu, Fedora, CentOS, etc.)

    Python 3.6+

    Доступ к sudo

    Интернет-соединение

Быстрый старт
bash

# Клонируйте репозиторий
git clone https://github.com/yourusername/bugbounty-setup.git
cd bugbounty-setup

# Запустите скрипт установки
python3 setup.py

Скрипт запросит права sudo для установки системных пакетов.
📁 Структура проекта

После выполнения скрипта создается следующая структура папок:
text

BugBounty_Workspace/
├── Web_catalog/          # Инструменты сканирования директорий
├── Subdomains/           # Поиск поддоменов
├── Scaner/               # Сканеры безопасности
├── CMS/                  # Инструменты для анализа CMS
├── SSRF/                 # Обнаружение SSRF уязвимостей
├── Open_redirect/        # Поиск open redirect уязвимостей
├── LFI/                  # Обнаружение LFI уязвимостей
├── XSS/                  # XSS сканеры и инструменты
├── SQLj/                 # SQL injection инструменты
└── JS/                   # Анализ JavaScript файлов

🛠️ Установленные инструменты
🔍 Web Catalog (Сканирование директорий)

    dirsearch - Advanced web path scanner

    ParamSpider - Parameter discovery suite

🌐 Subdomains (Поиск поддоменов)

    assetfinder - Subdomain discovery tool

    dalfox - Powerful XSS scanner

    subscraper - Multi-source subdomain enumerator

📡 Scanner (Сканеры безопасности)

    nmap - Network exploration tool

    subfinder - Subdomain discovery tool

    rustscan - Modern port scanner

    katana - Fast crawling framework

    lostools - Collection of OSINT tools

    PenHunter - Automated penetration testing tool

    argus - Security assessment framework

🎯 Specific Vulnerability Scanners
LFI (Local File Inclusion)

    LFIscanner - Automated LFI detection

    Lfi-Space - Advanced LFI exploitation

SQL Injection

    SQL-Injection-Finder - SQLi vulnerability detector

    sqlmap - Automatic SQL injection tool

XSS (Cross-Site Scripting)

    XSStrike - Advanced XSS detection suite

    dalfox - Parameter analysis and XSS scanning

SSRF (Server-Side Request Forgery)

    SSRFmap - Automatic SSRF exploitation tool

Open Redirect

    openredirex - Open redirect vulnerability scanner

JavaScript Analysis

    jshunter - JavaScript analysis tool

    Pinkerton - JS endpoint discovery

    SecretFinder - API key and secret finder

CMS Security

    wpprobe - WordPress security scanner

🚀 Использование

После установки все инструменты доступны в соответствующих папках:
bash

# Пример использования dirsearch
cd Web_catalog/dirsearch
python3 dirsearch.py -u https://example.com -e php,html,js

# Пример использования sqlmap
cd SQLj/sqlmap-dev
python3 sqlmap.py -u "https://example.com/page?id=1" --batch

# Пример использования XSStrike
cd XSS/XSStrike
python3 xsstrike.py -u "https://example.com/search?q=test"

Логи:

Скрипт выводит подробную информацию о процессе установки. Все ошибки логируются в консоль.

⚠️ Disclaimer

Этот инструмент предназначен только для образовательных целей и легального тестирования на проникновение. Используйте только на системах, где у вас есть явное разрешение на проведение тестов. Разработчик не несет ответственности за любое неправомерное использование.
