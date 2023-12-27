import re
from datetime import datetime

severity = {
    "INFO": "0",
    "ERROR": "10"
}

unique_ID = '0'

filename = 'log/eltex-ems/events.log'

lines = [
    '2023-12-21T16:50:12,215 [main] ERROR Kernel Server.main(line:234). EMS version (from server.jar manifest) : 3.31-11857 (29.09.23 16:41:32)',
    '2023-12-21T16:50:12,217 [main] ERROR Kernel Server$1.println(line:375). ----- test ERR ------- ',
    '2023-12-21T16:50:12,300 [main] ERROR Kernel Server.init(line:403). init: Server version = 3.31-11857 (29.09.23 16:41:32)',
    '2023-12-21T16:50:12,300 [main] ERROR Kernel Server.init(line:405). JAVA version = 1.8.0_362',
    '2023-12-21T16:50:13,772 [main] ERROR Kernel Server$1.println(line:375). [main] INFO com.zaxxer.hikari.HikariDataSource - tree - Starting...',
    '2023-12-21T16:50:13,793 [main] ERROR Kernel Server$1.println(line:375). [main] WARN com.zaxxer.hikari.util.DriverDataSource - Registered driver with driverClassName=org.gjt.mm.mysql.Driver was not found, trying direct instantiation.',
    '2023-12-21T16:50:15,352 [main] ERROR Kernel Server$1.println(line:375). [main] INFO com.zaxxer.hikari.HikariDataSource - tree - Start completed.',
    '2023-12-21T16:50:15,353 [main] ERROR Kernel Server$1.println(line:375). [main] INFO com.zaxxer.hikari.HikariDataSource - event - Starting...',
    '2023-12-21T16:50:15,390 [main] ERROR Kernel Server$1.println(line:375). [main] WARN com.zaxxer.hikari.util.DriverDataSource - Registered driver with driverClassName=org.gjt.mm.mysql.Driver was not found, trying direct instantiation.',
    '2023-12-21T16:50:15,435 [main] ERROR Kernel Server$1.println(line:375). [main] INFO com.zaxxer.hikari.HikariDataSource - event - Start completed.',
    '2023-12-21T16:50:15,437 [main] ERROR Kernel Server$1.println(line:375). [main] INFO com.zaxxer.hikari.HikariDataSource - ont - Starting...'
]


# Определение шаблона для разбора строки лога
log_pattern = re.compile(r'(?P<timestamp>\S+) \[\S+] (?P<level>\S+) (?P<name>[\s\S]+?)\)\. (?P<external>.*)')

for line in lines:
# Применение регулярного выражения к строке лога
    match = log_pattern.match(line)

    # Извлечение переменных из совпадения
    if match:
        timestamp = match.group('timestamp')
        level = match.group('level')
        name = match.group('name') + ')'  # Добавляем закрывающую скобку
        external = match.group('external') or 'null'

        data = {
            "timestamp": timestamp,
            "level": level,
            "name": name,
            "external": external
        }
    else:
        print("Строка лога не соответствует ожидаемому формату.")

    cef_header = 'CEF:0|Unknown|Unknown|Unknown|'

    event_name = data['name']
    log_level = data['level']

    unique_ID = str(int(unique_ID) + 1)

    timestamp = datetime.strptime(data['timestamp'], "%Y-%m-%dT%H:%M:%S,%f").strftime("%b %d %H:%M:%S")

    external = 'info=' + filename

    cef_message = timestamp + ' host ' + cef_header + unique_ID + '|' \
        + event_name + '|' + severity.get(log_level) + '|' + external

    print(cef_message)