import re
import configparser
from datetime import datetime
from pathlib import Path


file_paths = []
log_entries = []

CEF_output = []

unique_ID = "0"

vendor = 'Unknown'
version = 'Unknown'
show_lines = 'False'

pattern = re.compile(r'\[.*?\]')

severity = {
    "INFO": "0",
    "ERROR": "10"
}

un_ID = {
    "AUTHORIZATION": "100",
    "LOGIN": "101",
    "LOGOUT": "102",
    "PORTAL_CONSTRUCTOR_START": "103",
    "START": "104"
}


def get_settings(file_path='config.ini'):
    global vendor, version, show_lines, file_paths

    print("\n[SETTINGS]")
    print("   Reading settings from: " + file_path)
    check_path = Path(file_path)
    if check_path.exists():
        config = configparser.ConfigParser()
        config.read(file_path)

        try:
            vendor = config.get('Settings', 'vendor')
            version = config.get('Settings', 'version')
            show_lines = config.get('Mod', 'show_lines')
        except configparser.NoOptionError:
            print("   Some options in " + file_path + " was missed")

        try:
            file_paths = config.get('Paths', 'file_paths').split(', ')
        except configparser.NoOptionError:
            exit("Zero file_paths, check your " + file_path + " file and restart")
        print("   Settings was accepted")

    else:
        exit('There is no config file - '+file_path+', check README and restart')


def process_lines(lines, current_result=None):

    if current_result is None:
        current_result = []

    if not lines:
        return current_result

    current_line = lines[0]

    if not current_line.startswith("20"):
        if current_result:
            current_result[-1] += ' ' + current_line.strip()
        else:
            current_result.append(current_line.strip())
    else:
        current_result.append(current_line.strip())
    return process_lines(lines[1:], current_result)


def open_files(filename, selected_list):
    print("\n[OPENING FILE: "+filename+"]")
    try:
        with open(filename, 'r') as log_file:
            selected_list.clear()
            for line in log_file:
                selected_list.append(line)
            print("[PROCESSING LINES]")
            selected_list = process_lines(selected_list)
    except FileNotFoundError:
        exit(filename+" - is not exist, check your file or README for more information")


def remaking2(filename, list_with_lines):
    global unique_ID
    print("[START OF REMAKING LINES]")
    pattern = re.compile(r'\[(.*?)\]\[(.*?)\]')
    pattern_alternative = re.compile(r'(?P<timestamp>\S+) \[\S+] (?P<level>\S+) (?P<name>[\s\S]+?)\)\. (?P<external>.*)')

    for line in list_with_lines:
        if not line.startswith('20'):
            continue

        match = pattern.search(line)
        if match:
            timestamp, level, user_info, action_info = (
                line.split()[:2],
                line.split()[2],
                match.group(1),
                match.group(2)
            )
            data = {
                "timestamp": " ".join(timestamp),
                "level": level,
                "user_info": dict(re.findall(r'(\w+): "(.*?)"', user_info)),
                "action_info": dict(re.findall(r'(\w+): "(.*?)"', action_info))
            }
            if data['user_info']['host_ip'] == '':
                data['user_info']['host_ip'] = 'null'

            if data['user_info']['user_ip'] == '':
                data['user_info']['user_ip'] = 'null'

            cef_header = 'CEF:0|Unknown|Unknown|Unknown|'

            if "eltex-portal-constructor" in filename:
                cef_header = 'CEF:0|' + vendor + '|eltex-portal-constructor|' + version + '|'
                if 'portal-constructor.log' not in filename:
                    event_name = data['action_info']['msg']
            elif "eltex-ems" in filename:
                cef_header = 'CEF:0|' + vendor + '|eltex-ems|' + version + '|'
                event_name = data['action_info']['function']

            timestamp = datetime.strptime(data['timestamp'], "%Y-%m-%d %H:%M:%S,%f").strftime("%b %d %H:%M:%S")
            log_level = data['level']

            source = 'src=' + data['user_info']['host_ip']
            destination = 'dest=' + data['user_info']['user_ip']

            #unique_ID = str(int(unique_ID) + 1)
            if "eltex-portal-constructor" in filename:
                unique_ID = un_ID.get(data["action_info"]["action"])
            elif "eltex-ems" in filename:
                unique_ID = un_ID.get(data["action_info"]["function"])

            cef_message = timestamp + ' host ' + cef_header + unique_ID + '|' \
                          + event_name + '|' + severity.get(log_level) + '|' + source + ' ' \
                          + destination
        else:
            match = pattern_alternative.search(line)
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

            cef_header = 'CEF:0|Unknown|Unknown|Unknown|'
            if 'eltex-portal-constructor' in filename:
                cef_header = 'CEF:0|' + vendor + '|eltex-portal-constructor|' + version + '|'
            elif 'eltex-ems' in filename:
                cef_header = 'CEF:0|' + vendor + '|eltex-ems|' + version + '|'

            event_name = data['name']
            log_level = data['level']

            unique_ID = str(int(unique_ID) + 1)

            timestamp = datetime.strptime(data['timestamp'], "%Y-%m-%dT%H:%M:%S,%f").strftime("%b %d %H:%M:%S")

            external = 'info=' + filename

            cef_message = timestamp + ' host ' + cef_header + unique_ID + '|' \
                          + event_name + '|' + severity.get(log_level) + '|' + external

        CEF_output.append(cef_message)


def write_out_cef(cef_list):
    print("\n[WRITING NEW LINES TO THE FILE]")
    with open('cef_updated.log', 'w') as logfile:
        for line in cef_list:
            logfile.write(line+'\n')
    print("   Location of file: cef_updated.log")


'''----------------------------------------------------------------------------'''
get_settings()

for file in file_paths:
    open_files(file, log_entries)
    remaking2(file, log_entries)

write_out_cef(CEF_output)

if show_lines == 'True':
    for cef in CEF_output:
        print(cef)