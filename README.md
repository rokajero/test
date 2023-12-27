# New version of LOG Converter Script / Новая версия скрипта конвертирующего лог-файлы
---
## 1. Основная информация

В корневой папке расположены слежующие файлы:

    Log_converter                           - корневая директория
    ├── main.py                             - рабочий скрипт
    ├── README.md                           - README-файл
    ├── config.ini                          - конфиг для скрипта
    └── log                                 - папка с логами
        ├── eltex-ems                       - логи модуля EMS
        ├── eltex-portal-constructor        - логи модуля Portal Constructor
        └── __init__.py

**config.ini** используется для задания парамтеров **CEF header**'а, а также указания расположения лог-файлов, которые в дальнейшем будут конвертироваться в новый формат.

Так же есть дополнительный параметр **show_lines** в секции [Mod], который отвечает за вывод результатов в консоль.

Наличие конфиг файла - обязательно

В случае утери файла, следует создать новый файл формата ".ini" c названием "config". Внутрь файла следует внести следующие строки ->

```
[Settings]
vendor = Eltex
version = 1.27

[Paths]
file_paths = "путь к файлу(без кавычек, если несоклько, то через запятую, ниже закомментирован пример)"
#file_paths = log/eltex-portal-constructor/user-actions.log, log/eltex-ems/events.log

[Mod]
show_lines = False
```

Так же обязательное условие, распологать лог-журналы в следующем варианте:
корневая директория приложения -> log -> <Директория с названием модуля лог-файла> -> <лог-файл>

---
##### Программа имеет встроенные проверки, такие как:
Проверка на существование файла - в случае, если файл не будет обнаружен - необходимо проверить **config.ini** для сверки путей к журналам

Это может быть:
- неверно указанный путь к лог-файлу;
- не указаны никакие пути;

> В случае, если файл пустой - он будет пропущен.

---
##### Тестовые данные
Программа протестирована на следующих файлах:
- log/eltex-ems/events.log;
- log/eltex-portal-constructor/user-actions.log
- log/eltex-portal-constructor/portal-constructor.log

Данные файлы были получены из **ПО Eltex SoftWLC 1.27** в процессе работы сервера. Данный сервер был установлен на виртуальной машине под управлением **ОС Linux Ubuntu 18.04 LTS**.

---
##### Реализация перевода
Перевод журналов выполнен с использованием регулярных выржений. Программа написана на языке **Python 3.9** с использованием **IDE JetBrains PyCharm Community Edition 2023.1**.

Данная реализация не является конечным вариантом, так как реализация данного скрипта требует более углбленного изучения самого **ПО SoftWLC**, а также его механизмов логирования событий. Потому что в текущей ситуции журналы каждого модуля **SoftWLC** имеют свои отличительные особенности, которые затрудянют автоматизацию и использование регулярных выражений, из-за чего на данный момент полученную реализацию стоит называть ***"костыльной"***.
