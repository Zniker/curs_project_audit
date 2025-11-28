# Анализ событий безопасности ядра Linux при обращении к критическим файлам

Курсовой проект по теме:

> **«Анализ событий безопасности ядра Linux при обращении к критическим файлам с использованием подсистемы аудита Linux (auditd) и утилиты `ausearch`»**

Проект реализует небольшой **SOC-дашборд** для Linux-сервера:

- настраивает **auditd** на отслеживание обращений к критическим файлам;
- парсит лог `/var/log/audit/audit.log`;
- классифицирует события (нормальные / подозрительные / критические);
- сохраняет их в SQLite;
- отображает всё в графическом интерфейсе (PyQt6) с фильтрами и графиками.

---

## 1. Основная идея и сценарий

Мы предполагаем, что это **Linux-сервер** (например, Ubuntu 24.04):

- к нему подключаются пользователи по **SSH** или через локальную консоль;
- есть как минимум один администратор (root через `sudo`);
- возможны попытки НСД:
  - чтение `/etc/shadow` обычным пользователем,
  - изменение `sudoers`,
  - правка конфигурации SSH,
  - попытка подтереть логи.

**Уровень ядра** фиксирует только факты: «процесс X вызвал системный вызов доступа к файлу Y с такими-то правами».  
Задача проекта — **собрать эти события, классифицировать и удобно показать**.

---

## 2. Что умеет приложение

- Настройка Linux-аудита для отслеживания обращений к критическим файлам:
  - файлы учётных записей (`/etc/passwd`, `/etc/shadow`, …),
  - sudo (`/etc/sudoers`, `/etc/sudoers.d`),
  - SSH (`/etc/ssh/sshd_config`),
  - логи безопасности (`/var/log/auth.log`, `/var/log/audit/audit.log`).
- Парсинг лога **`/var/log/audit/audit.log`** (подсистема auditd).
- Классификация событий по правилам:
  - **тип события**: `accounts`, `privilege`, `remote_access`, `logging`;
  - **классификация**: `normal` / `suspicious`;
  - **уровень**: `OK`, `WARNING`, `CRITICAL`.
- Сохранение событий в **SQLite** (через SQLAlchemy).
- Графический интерфейс на **PyQt6**:
  - таблица событий с цветовой подсветкой;
  - фильтры:
    - по классификации (все / подозрительные / нормальные),
    - по типу события,
    - по UID;
  - верхние KPI (Всего / Подозрительных / Критичных);
  - графики:
    - динамика событий (накопленное количество),
    - pie-chart по уровням;
  - окно **«Подробности события»** по двойному клику.

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


