from email import header
import paramiko
from scp import SCPClient
import subprocess
import sys
import os
import tarfile
import plistlib
import configparser
import re
import magic
import sqlite3
import readline
import glob

def get_config_defaults():
    config = configparser.ConfigParser()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.ini')
    
    if not os.path.exists(config_path):
        print(f"[!] Warning: {config_path} not found. Using defaults.")
    
    config.read(config_path)
    
    # Use .get() then convert manually to be 100% safe
    hide_val = config.get('SETTINGS', 'HIDE_APPLE_PACKAGES', fallback='False').lower()
    hide_bool = hide_val in ['true', 'yes', '1', 'on']

    return {
        "ip": config.get('CONNECTION', 'IP', fallback=''),
        "port": config.get('CONNECTION', 'PORT', fallback='22'),
        "user": config.get('CONNECTION', 'USER', fallback='root'),
        "pass": config.get('CONNECTION', 'PASSWORD', fallback='alpine'),
        "hide_apple": hide_bool
    }

def enumerate_ios(package_name, output_dir, ip, port, user, password):
    # (Same as your original code, provided for context)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"    [*] Connecting to {ip}...")
        ssh.connect(ip, port=int(port), username=user, password=password)
        search_roots = {
            "data":"/private/var/mobile/Containers/Data/Application",
            "bundle":"/private/var/containers/Bundle/Application"
        }
        for label, root in search_roots.items():
            cmd = f"find {root} -name '.com.apple.mobile_container_manager.metadata.plist' -exec grep -l '{package_name}' {{}} + | xargs dirname"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            paths = stdout.read().decode().splitlines()
            if not paths:
                continue
            for p in paths:
                extract_ios_files(p, output_dir, ssh, label)
    except Exception as e:
        print(f"     [!] SSH Error: {e}")
    finally:
        ssh.close()

def extract_ios_files(path, output_dir, ssh, label):
    archive_name = f"iOS_{label}.tar"
    remote_tmp_path = f"/tmp/{archive_name}"
    
    # Base folder for logs (e.g., .../output/iOS/)
    ios_root = os.path.join(output_dir, "iOS")
    # Folder for extracted files (e.g., .../output/iOS/data/)
    local_extraction_root = os.path.join(ios_root, label)
    
    if not os.path.exists(local_extraction_root):
        os.makedirs(local_extraction_root)

    try:
        remote_parent_dir = os.path.dirname(path)
        folder_name = os.path.basename(path)
        
        print(f"    [*] Archiving {label} folder ({folder_name}) on iPhone...")
        tar_cmd = f"tar -cf {remote_tmp_path} -C {remote_parent_dir} {folder_name}"
        stdin, stdout, stderr = ssh.exec_command(tar_cmd)
        
        if stdout.channel.recv_exit_status() == 0:
            local_tar_path = os.path.join(local_extraction_root, archive_name)
            print(f"    [*] Downloading to {local_tar_path}...")
            
            with SCPClient(ssh.get_transport()) as scp:
                scp.get(remote_tmp_path, local_path=local_tar_path)
                
            print(f"    [*] Extracting files locally...")
            with tarfile.open(local_tar_path, "r:") as tar:
                if hasattr(tarfile, 'data_filter'):
                    # filter prevents tar bombs from overwirting system files. 
                    tar.extractall(path=local_extraction_root, filter="tar")
                else:
                    # Fallback for older Python versions
                    tar.extractall(path=local_extraction_root)
            
            actual_local_files = os.path.join(local_extraction_root, folder_name)
            print(f"        [+] Extraction successful: {actual_local_files}")

            ssh.exec_command(f"rm {remote_tmp_path}")
            
            # --- Analysis Logic ---
            # We pass ios_root for logs, but actual_local_files for scanning
            print(f"    [*] Searching for database files...")
            db_log = enumerate_db(actual_local_files, ios_root)
            
            print(f"    [*] Extracting plists from DBs...")
            db_extract_plists(ios_root, db_log)

            print(f"    [*] Searching for embedded plists...")
            parse_plists(actual_local_files, ios_root)

    except Exception as e:
        print(f"    [!] Extraction failed: {e}")

def parse_plists(scan_dir, log_dir):
    log_file = os.path.join(log_dir, "plist_files.txt")
    
    for root, dirs, files in os.walk(scan_dir):
        for file in files:
            file_path = os.path.join(root, file)
            is_plist = file.endswith('.plist')
            
            if not is_plist:
                try:
                    with open(file_path, 'rb') as f:
                        header = f.read(8)
                        if header.startswith(b'bplist') or header.startswith(b'<?xml'):
                            is_plist = True
                except: continue

            if is_plist:
                rel_path = os.path.relpath(file_path, log_dir)
                
                try:
                    with open(log_file, "a", encoding="utf-8") as f_log:
                        f_log.write(rel_path + "\n")
                    
                    extract_embedded_plists(file_path, log_file, log_dir)
                    convert_plistXML(file_path)
                except: continue

    print(f"        [+] Plists processed. Log: {log_file}")

def convert_plistXML(file_path):
    def patch_uid(obj):
        if isinstance(obj, dict):
            return {k: patch_uid(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [patch_uid(x) for x in obj]
        # Check if the object is a UID (common in keyed archives)
        elif hasattr(obj, 'data') and 'UID' in str(type(obj)):
            return obj.data
        return obj

    try:
        with open(file_path, 'rb') as f:
            data = plistlib.load(f)
        
        # Clean the data of unsupported UID types
        patched_data = patch_uid(data)
        
        with open(file_path, 'wb') as f:
            plistlib.dump(patched_data, f, fmt=plistlib.FMT_XML)
            
    except Exception as e:
        print(f"        [!] Failed to convert:\n        {file_path}\n        {e}")

def extract_embedded_plists(file_path, log_file, log_dir):
    def find_and_save_blobs(obj, parent_path, count):
        if isinstance(obj, dict):
            for k, v in obj.items():
                count = find_and_save_blobs(v, f"{parent_path}_{k}", count)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                count = find_and_save_blobs(v, f"{parent_path}_{i}", count)
        elif isinstance(obj, bytes) and obj.startswith(b'bplist00'):
            try:
                embedded_plist = plistlib.loads(obj)
                out_name = f"{file_path}_extracted_{count}.plist"
                
                with open(out_name, 'wb') as out_f:
                    plistlib.dump(patch_uid(embedded_plist), out_f, fmt=plistlib.FMT_XML)
                
                # --- CALC RELATIVE PATH ---
                rel_out_path = os.path.relpath(out_name, log_dir)
                
                with open(log_file, "a", encoding="utf-8") as f_log:
                    f_log.write(rel_out_path + "\n")
                
                print(f"        [+] Extracted: {rel_out_path}")
                count += 1
                count = find_and_save_blobs(embedded_plist, out_name, count)
            except:
                pass
        return count

    try:
        with open(file_path, 'rb') as f:
            data = plistlib.load(f)
        find_and_save_blobs(data, file_path, 1)
    except:
        # Fallback for concatenated files (like data.data)
        raw_byte_scan(file_path, log_file, log_dir)

def raw_byte_scan(file_path, log_file, log_dir):
    BPLIST_MAGIC = b'bplist00'
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        matches = [m.start() for m in re.finditer(BPLIST_MAGIC, content)]
        if not matches or (len(matches) == 1 and matches[0] == 0):
            return

        for i, start_index in enumerate(matches):
            if start_index == 0: continue 
            try:
                sub_data = content[start_index:]
                plist_data = plistlib.loads(sub_data)
                out_name = f"{file_path}_raw_{i}.plist"
                
                with open(out_name, 'wb') as out_f:
                    plistlib.dump(patch_uid(plist_data), out_f, fmt=plistlib.FMT_XML)
                
                # --- CALC RELATIVE PATH ---
                rel_out_path = os.path.relpath(out_name, log_dir)
                
                with open(log_file, "a", encoding="utf-8") as f_log:
                    f_log.write(rel_out_path + "\n")
            except: continue
    except: pass
    """Fallback for files that aren't plists but contain plists (concatenated)"""
    BPLIST_MAGIC = b'bplist00'
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        matches = [m.start() for m in re.finditer(BPLIST_MAGIC, content)]
        # If the file starts with bplist and has no other matches, we already processed it
        if not matches or (len(matches) == 1 and matches[0] == 0):
            return

        for i, start_index in enumerate(matches):
            if start_index == 0: continue 
            try:
                sub_data = content[start_index:]
                plist_data = plistlib.loads(sub_data)
                out_name = f"{file_path}_raw_{i}.plist"
                with open(out_name, 'wb') as out_f:
                    plistlib.dump(patch_uid(plist_data), out_f, fmt=plistlib.FMT_XML)
                with open(log_file, "a", encoding="utf-8") as f_log:
                    f_log.write(out_name + "\n")
            except: continue
    except: pass

def db_extract_plists(output_dir, log_file):
    new_folder = os.path.join(output_dir, "db_extracted_plists")
    os.makedirs(new_folder, exist_ok=True)
    
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            relative_path = line.strip()
            # Construct the absolute path to the local extracted file
            file_path = os.path.join(output_dir, relative_path)
            
            if not os.path.exists(file_path):
                print(f"    [!] File not found: {file_path}")
                continue

            base_name = os.path.basename(file_path)
            output_subdir = os.path.join(new_folder, f"{base_name}_plists")
            os.makedirs(output_subdir, exist_ok=True)
            try:
                conn = sqlite3.connect(file_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                for table_name in tables:
                    table = table_name[0]
                    cursor.execute(f"PRAGMA table_info('{table}');")
                    columns = cursor.fetchall()
                    for column in columns:
                        col_name = column[1]
                        cursor.execute(f"SELECT {col_name} FROM {table};")
                        rows = cursor.fetchall()
                        for idx, row in enumerate(rows):
                            data = row[0]
                            if isinstance(data, bytes) and data.startswith(b'bplist00'):
                                try:
                                    plist_data = plistlib.loads(data)
                                    out_name = os.path.join(output_subdir, f"{table}_{col_name}_row{idx+1}.plist")
                                    with open(out_name, 'wb') as out_f:
                                        plistlib.dump(plist_data, out_f, fmt=plistlib.FMT_XML)
                                except Exception:
                                    continue
                conn.close()
            except Exception as e:
                print(f"         [!] Failed to extract plists from {file_path}: {e}")
        print(f"        [+] Extracted plists from DB to: {new_folder}")

def enumerate_db(scan_dir, log_dir):
    log_file = os.path.join(log_dir, "DB_files.txt")
    
    with open(log_file, "a", encoding="utf-8") as f_log:
        f_log.write(f"")

    for root, dirs, files in os.walk(scan_dir):
        for file in files:
            file_path = os.path.join(root, file)
            is_db = file.lower().endswith(('.db', '.sqlite', '.sqlite3'))
            
            if not is_db:
                try:
                    with open(file_path, 'rb') as f:
                        if f.read(16).startswith(b'SQLite format 3'):
                            is_db = True
                except: continue

            if is_db:
                rel_path = os.path.relpath(file_path, log_dir)
                
                with open(log_file, "a", encoding="utf-8") as f_log:
                    f_log.write(rel_path + "\n")
    return log_file

def enumerate_android(package_name, output_path):
    print(f"    [*] Targeting Android for package: {package_name}")
    
    search_roots = [
        {"path": f"/data/user/0/{package_name}", "label": "data"},
        {"path": f"/storage/emulated/0/Android/data/{package_name}", "label": "storage"}
    ]
    
    android_out = os.path.join(output_path, "Android")
    os.makedirs(android_out, exist_ok=True)

    for item in search_roots:
        remote_path = item["path"]
        label = item["label"]
        
        # Check existence via adb shell
        check_cmd = ["adb", "shell", f"su -c 'ls -d {remote_path}'"]
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"        [+] Found path: {remote_path}")
            extract_android_files(remote_path, label, android_out)
        else:
            # Fallback for non-root external storage
            if label == "storage":
                print(f"    [*] Trying {label} without root...")
                check_no_root = ["adb", "shell", f"ls -d {remote_path}"]
                if subprocess.run(check_no_root, capture_output=True).returncode == 0:
                    extract_android_files(remote_path, label, android_out)
            else:
                print(f"    [!] Path inaccessible: {remote_path}")

def extract_android_files(remote_path, label, output_path):
    print(f"    [*] Pulling {label} from {remote_path} to {output_path}...")
    
    # Use adb to tar, pull, and cleanup Android device
    compress_cmd = ["adb", "shell", f"su -c 'tar -cf /data/local/tmp/{label}.tar {remote_path}'"]
    pull_cmd = ["adb", "pull", f"/data/local/tmp/{label}.tar", output_path]
    cleanup_cmd = ["adb", "shell", f"su -c 'rm /data/local/tmp/{label}.tar'"]
    
    try:
        #run commands, supressing output and errors 
        subprocess.run(compress_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(pull_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cleanup_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # extract the contents of the tar
        local_tar_path = os.path.join(output_path, f"{label}.tar")
        with tarfile.open(local_tar_path, "r:") as tar:
            for member in tar.getmembers():
                if member.isfile() or member.isdir() or member.islnk() or member.issym():
                    try:
                        tar.extract(member, path=output_path)
                    except Exception:
                        pass 
        print(f"        [+] Extraction successful: {output_path}")
        local_cleanup = ["rm", local_tar_path]
        subprocess.run(local_cleanup)
        print(f"    [*] Looking for DB files")
        enumerate_db(output_path, output_path)
    except Exception as e:
        print(f"    [!] Pull failed: {e}")

def enumeratePackages(is_ios, ip, port, user, password, hide_apple=False):
    package_list = []
    if is_ios:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, port=int(port), username=user, password=password)
            find_cmd = "find /var/mobile/Containers/Data/Application/ -name '.com.apple.mobile_container_manager.metadata.plist'"
            stdin, stdout, stderr = ssh.exec_command(find_cmd)
            plist_files = stdout.read().decode().splitlines()

            # Updated regex to be slightly more restrictive
            id_regex = re.compile(rb'com\.[a-zA-Z0-9\.-]+')
            
            for plist in plist_files:
                stdin, stdout, stderr = ssh.exec_command(f"cat '{plist}'")
                raw_data = stdout.read() 
                matches = id_regex.findall(raw_data)
                
                for m in matches:
                    pkg_id = m.decode('utf-8', 'ignore').strip().rstrip('.')
                    
                    # Check if it's an Apple package
                    is_apple = pkg_id.lower().startswith('com.apple.')
                    
                    # LOGIC: If hide_apple is True AND it is an apple package, SKIP IT
                    if hide_apple and is_apple:
                        continue
                    
                    # Only add valid looking bundle IDs
                    if pkg_id.count('.') >= 2 and len(pkg_id) > 7:
                        package_list.append(pkg_id)

        except Exception as e:
            print(f"     [!] Could Not Connect to SSH")
            sys.exit(0)
            #print(f"[!] Error: {e}")
        finally:
            ssh.close()
    else:
        # Android Logic
        list_cmd = ["adb", "shell", "pm", "list", "packages"]
        try:
            result = subprocess.run(list_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    pkg_id = line.replace('package:', '')
                    # Optional: Apply similar filter for Android system apps
                    if hide_apple and (pkg_id.startswith('com.android.') or pkg_id.startswith('com.google.')):
                        continue
                    package_list.append(pkg_id)
        except Exception as e:
            print(f"[!] ADB Error: {e}")
    
    return sorted(list(set(package_list)))

def path_completer(text, state):
    orig_text = text
    expanded = os.path.expanduser(text)
    matches = glob.glob(expanded + '*')

    results = []
    for m in matches:
        if os.path.isdir(m):
            m += '/'
        # correcting phantom characters, keeping relative path the same rather than overwriting with absolute path
        if orig_text.startswith('~'):
            home = os.path.expanduser('~')
            m = m.replace(home, '~', 1)
        results.append(m)

    try:
        return results[state]
    except IndexError:
        return None

def patch_uid(obj):
    # Recursively converts Apple UID objects to standard data types for XML export
    if isinstance(obj, dict):
        return {k: patch_uid(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [patch_uid(x) for x in obj]
    elif hasattr(obj, 'data') and 'UID' in str(type(obj)):
        return obj.data
    return obj

def extension_search(search_dir, defaults):
    logs = ['DB_files.txt', 'plist_files.txt', 'extension_search.txt', 'string_search.txt']
    log_file_path = os.path.join(search_dir, "extension_search.txt")
    if defaults == 'y' or defaults == '':
        extensions = ['.txt', '.json', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.xml', '.log']
    else:
        extensions = []
        while True:
            ext = input("Enter extension (e.g., .db, .json) or 'done' to continue: ").strip()
            if ext.lower() == "exit":
                return
            if ext.lower() == "done" or ext == "":
                break
            if ext:
                if not ext.startswith('.'):
                    ext = f".{ext}"
                extensions.append(ext)

            else:
                break

    if not extensions:
        print("    [!] No extensions provided. Returning to menu.")
        return
    with open(log_file_path, 'a', encoding='utf-8') as f:
        header = ", ".join(extensions)
        f.write(f"\n--- Search for: {header} ---\n")
        for root, dirs, files in os.walk(search_dir):
            for file in files:
                if file in logs:
                        continue
                if any(file.lower().endswith(ext) for ext in extensions):
                    rel_path = os.path.relpath(os.path.join(root, file), search_dir)
                    f.write(rel_path + '\n')
        print(f"        [+] Extension search complete. Log: {log_file_path}")

def string_search(search_dir):
    log_file_path = os.path.join(search_dir, "string_search.txt")
    logs = ['DB_files.txt', 'plist_files.txt', 'extension_Search.txt', 'string_search.txt']
    while True:
        search_string = input("Enter string to search for (or 'exit' to return): ").strip()
        if search_string.lower() == "exit" or search_string == "":
            print("    [!] No search string provided. Returning to menu.")
            return
        with open(log_file_path, 'a', encoding='utf-8') as log:
            log.write(f"\n--- Search for: {search_string} ---\n")
            for root, dirs, files in os.walk(search_dir):
                for file in files:
                    # Avoid catching strings within our own log files.
                    if file in logs:
                        continue
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # Case-insensitive search
                            if search_string.lower() in content.lower():
                                rel_path = os.path.relpath(file_path, search_dir)
                                print(f"        [+] Found in: {rel_path}")
                                log.write(rel_path + '\n')
                    except: continue

def interactive_session():
    header = r"""
-----------------------------------------------
      __  __  ____  ____  _____ _      ______ 
     |  \/  |/ __ \|  _ \|_   _| |    |  ____|
     | \  / | |  | | |_) | | | | |    | |__   
     | |\/| | |  | |  _ <  | | | |    |  __|  
     | |  | | |__| | |_) |_| |_| |____| |____ 
     |_|  |_|\____/|____/|_____|______|______|
            > MOBILE_DATA_EXTRACTOR_v1 <
-----------------------------------------------
    """
    print(header)
    print("Setting up device config")
    # 1. Platform
    p_choice = input("    [1. Android]\n    [2. iOS]\n What platform: ").strip()
    is_ios = (p_choice == "2" or p_choice.lower() == "ios")
    
    # 2. Config for iOS
    conf = get_config_defaults()
    ip, port, user, password = conf['ip'], conf['port'], conf['user'], conf['pass']
    hide_apple = conf['hide_apple']

    if is_ios:
        print("\n--- Current iOS Connection Settings ---")
        print(f"  IP Address : {ip if ip else '[NOT SET]'}")
        print(f"  Port       : {port}")
        print(f"  Username   : {user}")
        print(f"  Password   : {password}")
        print(f"  Filter Apple: {'ENABLED' if hide_apple else 'DISABLED'}")
        print("-" * 39)
        
        if input("Overwrite these settings? [y/N]: ").lower() == 'y':
            ip = input(f"IP [{ip}]: ") or ip
            port = input(f"Port [{port}]: ") or port
            user = input(f"User [{user}]: ") or user
            password = input(f"Password [{password}]: ") or password
            filter_prompt = input(f"Hide Apple Packages (com.apple.*) [Y/n]?: ").lower()
            if filter_prompt in ['y', 'yes']:
                hide_apple = True
            elif filter_prompt in ['n', 'no']:
                hide_apple = False

    # 3. Enumeration
    available_packages = []
    if input("\nDo you want to enum packages [y/N]: ").lower() == 'y':
        print("[*] Enumerating...")
        available_packages = enumeratePackages(is_ios, ip, port, user, password, hide_apple)
        if not available_packages:
            print("[-] No packages found.")
        else:
            for idx, pkg in enumerate(available_packages, 1):
                print(f"{idx:3}. {pkg}")

    # 4. Package Selection
    package_to_test = ""
    if available_packages:
        while True:
            sel = input(f"\nEnter the number of the package (1-{len(available_packages)}): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(available_packages):
                package_to_test = available_packages[int(sel)-1]
                break
            print("[!] Invalid selection.")
    else:
        package_to_test = input("\nWhat package do you want to test? (Bundle ID): ").strip()

    if not package_to_test:
        print("     [!] No package provided. Exiting.")
        return

    # 5. Output directory
    default_out = os.getcwd()
    readline.set_completer_delims(' \t\n;')

    # setup autocomplete for user input
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")

    readline.set_completer(path_completer)
    output_path = input(f"\nOutput directory [{default_out}]: ").strip() or default_out
    expanded_path = os.path.expanduser(output_path)
    output_path = os.path.abspath(expanded_path)

    # 6. Run
    print(f"\n    [*] Starting extraction for {package_to_test}...")
    if is_ios:
        enumerate_ios(package_to_test, output_path, ip, port, user, password)
    else:
        enumerate_android(package_to_test, output_path)

    # 7. Next Steps 
    if is_ios:
        output_path = os.path.join(output_path, 'iOS')
    else:
        output_path = os.path.join(output_path, 'Android')
    while True:
        choice = input("\nWhat do you want to do next?\n"
                    "   [1. Search for File Extensions]\n"
                    "   [2. Search for Strings]\n"
                    "   [3. Exit]\n"
                    "Choice: ").strip()

        if choice == '1':
                default_ext_search = input("Search for default extensions (.txt, .json, .pdf, .doc, .docx, .ppt, .xls, .xlsx, .xml, .log)? [Y/n]: ").strip().lower()
                extension_search(output_path, default_ext_search)
        elif choice == '2':
            string_search(output_path)
        elif choice == '3' or choice.lower() == 'exit':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

    footer = r"""
-------------------------------------------
Done!
-------------------------------------------
    """
    print(footer)

if __name__ == "__main__":
    try:
        interactive_session()
    except KeyboardInterrupt:
        print("\n[!] User aborted.")
        sys.exit(0)