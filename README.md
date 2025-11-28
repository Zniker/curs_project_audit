# Анализ событий безопасности ядра Linux при обращении к критическим файлам

Курсовой проект по теме:

> **«Анализ событий безопасности ядра Linux при обращении к критическим файлам с использованием подсистемы аудита Linux (auditd) и утилиты `ausearch`»**

Провести анализ событий безопасности ядра Linux при обращении к критическим файлам с использованием подсистемы аудита Linux (auditd) и утилиты ausearch. Разработать методику выявления несанкционированных обращений и программу для классификации и хранения событий. Реализовать графический интерфейс для визуализации результатов. Провести отладку и тестирование программы, загрузить проект в репозиторий github.com и оформить отчёт.

---

## 1. Основная идея и сценарий

Проект предназначен для мониторинга обращений к критически важным файлам Linux (например, Ubuntu 24.04), где одновременно работают обычные пользователи и администратор (root через sudo).  
В такой среде возможны различные попытки несанкционированных действий, среди которых:

- чтение файлов учётных записей (`/etc/shadow`, `/etc/gshadow`) обычным пользователем;
- изменение настроек привилегий (`/etc/sudoers`);
- вмешательство в конфигурацию SSH (`/etc/ssh/sshd_config`);
- попытки удаления или модификации журналов (`/var/log/auth.log`, `/var/log/audit/audit.log`).

Подсистема аудита ядра (`auditd`) регистрирует вызовы, связанные с этими файлами, но журнал представляет собой множество разрозненных строк, которые сложно анализировать вручную.

**Основная идея проекта** — автоматически собрать и классифицировать события аудита, а затем визуализировать их в удобной SOC-панели для оперативного выявления подозрительных действий.

---

## 2. Возможности приложения

### 2.1. Мониторинг критических файлов
Приложение отслеживает обращение к следующим категориям файлов:

- **Учётные записи:**
  - `/etc/passwd`
  - `/etc/shadow`
  - `/etc/group`
  - `/etc/gshadow`
- **Права привилегий:**
  - `/etc/sudoers`
  - `/etc/sudoers.d/`
- **Удалённый доступ:**
  - `/etc/ssh/sshd_config`
- **Журналы системы:**
  - `/var/log/auth.log`
  - `/var/log/audit/audit.log`

Список критических файлов вынесен в конфигурационный файл `critical_files.yaml`.

### 2.2. Обработка событий auditd

Приложение выполняет:

- чтение журнала `/var/log/audit/audit.log`;
- группировку строк в единое событие по `audit_id`;
- извлечение ключевых параметров:
  - UID / AUID,
  - процесс (`exe`, `comm`),
  - файл (`path`),
  - тип доступа,
  - успешность вызова,
  - ключ правила (`key`).

### 2.3. Классификация событий

События распределяются:

- **по типу:**
  - `accounts`
  - `privilege`
  - `remote_access`
  - `logging`

- **по уровню:**
  - `OK`
  - `WARNING`
  - `CRITICAL`

Критичность зависит от:
- категории файла;
- привилегий и роли пользователя;
- доверенности процесса;
- типа операции (чтение / запись / модификация).

### 2.4. Хранение данных

Используется база SQLite:

- все события сохраняются через ORM SQLAlchemy;
- предотвращается дублирование записей (проверка по `audit_id`);
- база легко переносится (один файл `audit.db`).

### 2.5. SOC-панель (графический интерфейс)

Приложение предоставляет полноценный интерфейс для оперативного анализа:

- **таблица событий** с цветовым кодированием по уровню;
- **фильтры**:
  - классификация,
  - тип события,
  - UID пользователя;
- **верхняя панель KPI:**
  - всего событий,
  - подозрительных,
  - критичных;
- **графики:**
  - динамика событий (все / подозрительные),
  - распределение по уровням (pie-chart);
- **окно подробностей события** — открывается по двойному клику.
  
---

## 3. Используемые технологии

- **Linux audit subsystem** (`auditd`, `ausearch`)
- **Python 3**
- **PyQt6**, **PyQt6-Charts**
- **SQLAlchemy** (SQLite)
- **PyYAML** (конфиг критических файлов)

---

## 4. Установка и запуск

### 4.1. Клонирование репозитория

```bash
git clone https://github.com/Zniker/curs_project_audit.git
cd curs_project_audit
продолжение следует...
```
## 5. Структура проекта

```text
curs_project_audit/
├── app/
│   ├── __init__.py
│   ├── parser.py          # парсер журнала /var/log/audit/audit.log
│   ├── classifier.py      # классификация событий, загрузка critical_files.yaml
│   ├── models.py          # ORM-модель AuditEvent (SQLAlchemy)
│   └── gui.py             # графический интерфейс (PyQt6)
├── critical_files.yaml    # конфигурация критических файлов
├── import_events.py       # импорт событий аудита в SQLite
├── init_db.py             # создание структуры базы данных
├── run.py                 # точка входа: запуск GUI
├── requirements.txt       # зависимости Python
└── README.md
```
## 6. Конфигурация критических файлов (`critical_files.yaml`)

Список критических файлов хранится не в коде, а в отдельном YAML-файле:

```yaml
files:
  # --- accounts ---
  - path: "/etc/passwd"
    category: "accounts"
    base_weight: 70
    description: "Список пользователей, shell, домашние директории"

  - path: "/etc/shadow"
    category: "accounts"
    base_weight: 95
    description: "Хэши паролей пользователей"

  - path: "/etc/group"
    category: "accounts"
    base_weight: 65
    description: "Группы и членство"

  - path: "/etc/gshadow"
    category: "accounts"
    base_weight: 80
    description: "Секреты групп"

  # --- privilege ---
  - path: "/etc/sudoers"
    category: "privilege"
    base_weight: 95
    description: "Права sudo"

  - path: "/etc/sudoers.d"
    category: "privilege"
    base_weight: 90
    description: "Дополнительные правила sudo"

  # --- remote access ---
  - path: "/etc/ssh/sshd_config"
    category: "remote_access"
    base_weight: 85
    description: "Конфигурация SSH сервера"

  # --- logging ---
  - path: "/var/log/auth.log"
    category: "logging"
    base_weight: 70
    description: "Лог аутентификации"

  - path: "/var/log/audit/audit.log"
    category: "logging"
    base_weight: 80
    description: "Лог аудита"
```
## 7. Настройка auditd

Конфигурация правил аудита размещается в файле:

/etc/audit/rules.d/critical-files.rules

Ниже приведён полный набор правил, отслеживающих операции чтения и модификации критически важных файлов.

```text
## ACCOUNTS
-a always,exit -F path=/etc/passwd  -F perm=r -F auid>=1000 -F auid!=4294967295 -k critical_files
-a always,exit -F path=/etc/shadow  -F perm=r -F auid>=1000 -F auid!=4294967295 -k critical_files
-a always,exit -F path=/etc/group   -F perm=r -F auid>=1000 -F auid!=4294967295 -k critical_files
-a always,exit -F path=/etc/gshadow -F perm=r -F auid>=1000 -F auid!=4294967295 -k critical_files

-a always,exit -F path=/etc/passwd  -F perm=w -F auid!=4294967295 -k critical_files
-a always,exit -F path=/etc/shadow  -F perm=w -F auid!=4294967295 -k critical_files
-a always,exit -F path=/etc/group   -F perm=w -F auid!=4294967295 -k critical_files
-a always,exit -F path=/etc/gshadow -F perm=w -F auid!=4294967295 -k critical_files

## PRIVILEGE
-a always,exit -F path=/etc/sudoers -F perm=wa -F auid!=4294967295 -k critical_files
-w /etc/sudoers.d -p wa -k critical_files

## REMOTE ACCESS
-a always,exit -F path=/etc/ssh/sshd_config -F perm=wa -F auid!=4294967295 -k critical_files

## LOGGING
-a always,exit -F path=/var/log/auth.log        -F perm=wa -F auid!=4294967295 -k critical_files
-a always,exit -F path=/var/log/audit/audit.log -F perm=wa -F auid!=4294967295 -k critical_files

```
## 9. Интерфейс SOC-панели

### 9.1. Общее окно

SOC-панель представляет собой основное окно приложения, включающее:

- **заголовок и KPI-метрики:**
  - общее количество событий;
  - число подозрительных событий;
  - число критичных (операции с критическими файлами);
- **панель фильтров:**
  - Классификация — *all / suspicious / normal*;
  - Тип события — *accounts / privilege / remote_access / logging / all*;
  - UID — выбор конкретного пользователя;
- **таблицу событий** (центральная часть окна);
- **правую боковую панель графиков:**
  - динамика событий (все / подозрительные);
  - круговая диаграмма распределения по уровням.

<img width="2235" height="1229" alt="image" src="https://github.com/user-attachments/assets/79ce9241-cb6f-421b-ab46-d234ba964350" />

---

### 9.2. Таблица событий

Табличное представление содержит следующие столбцы:

- ID события (внутренний ID в SQLite);
- Время;
- UID;
- AUID;
- Процесс (`exe`);
- Файл;
- Тип события *(accounts, privilege, remote_access, logging)*;
- Уровень *(OK / WARNING / CRITICAL)*;
- Классификация *(normal / suspicious)*.

Для удобства восприятия используются цветовые маркеры строк:

- **зелёный** — OK;
- **оранжевый** — WARNING;
- **красный** — CRITICAL.
  
<img width="1399" height="763" alt="image" src="https://github.com/user-attachments/assets/83b8c143-0f28-4250-b264-05ad3f196416" />

---

### 9.3. Подробности события

При двойном клике по строке открывается отдельное окно с расширенной информацией:

- ID и точное время события;
- UID и AUID;
- процесс и команда (`comm`);
- номер системного вызова (`syscall`);
- путь к файлу, права доступа (`perm`), ключ (`key`);
- тип события и итоговая классификация;
- поле **reason** — текстовое объяснение, почему событие классифицировано именно так.


<img width="1518" height="681" alt="image" src="https://github.com/user-attachments/assets/956a54d3-fa44-42df-aea4-e630543b6038" />

---

### 9.4. Графики

В SOC-панели предусмотрены два основных графика:

#### • **Line-chart динамики событий**
- Ось X — время / индекс события.
- Ось Y — накопленное количество.
- Две линии:
  - зелёная — все события,
  - красная — подозрительные.

#### • **Pie-chart распределения**
Показывает долю:

- Normal  
- Warning  
- Critical  

<img width="736" height="1108" alt="image" src="https://github.com/user-attachments/assets/10bd3b72-ad25-4667-a6a0-f84f5abe89a0" />


