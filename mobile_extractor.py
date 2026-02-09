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
        search_roots = [
            "/private/var/mobile/Containers/Data/Application",
            "/private/var/containers/Bundle/Application"
        ]
        for root in search_roots:
            cmd = f"find {root} -name '.com.apple.mobile_container_manager.metadata.plist' -exec grep -l '{package_name}' {{}} + | xargs dirname"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            paths = stdout.read().decode().splitlines()
            if not paths:
                continue
            for p in paths:
                extract_ios_files(p, output_dir, ip, port, user, password)
    except Exception as e:
        print(f"     [!] SSH Error: {e}")
    finally:
        ssh.close()

def extract_ios_files(path, output_dir, ip, port, user, password):
    archive_name = "iOS_data_bundle.tar"
    remote_tmp_path = f"/tmp/{archive_name}"
    local_path = os.path.join(output_dir, "iOS")
    
    if not os.path.exists(local_path):
        os.makedirs(local_path)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(ip, port=int(port), username=user, password=password)
        
        print(f"    [*] Archiving {path} on iPhone...")
        formatted_path = path.lstrip('/')
        tar_cmd = f"tar -cf {remote_tmp_path} -C / {formatted_path}"
        stdin, stdout, stderr = ssh.exec_command(tar_cmd)
        
        if stdout.channel.recv_exit_status() == 0:
            local_tar_path = os.path.join(local_path, archive_name)
            print(f"    [*] Downloading bundle to {local_tar_path}...")
            
            with SCPClient(ssh.get_transport()) as scp:
                scp.get(remote_tmp_path, local_path=local_tar_path)
                
            with tarfile.open(local_tar_path, "r:") as tar:
                for member in tar.getmembers():
                    if member.isfile() or member.isdir() or member.islnk() or member.issym():
                        try:
                            tar.extract(member, path=local_path)
                        except Exception:
                            pass 
            
            print(f"    [+] Extraction successful in: {local_path}")
            # cleanup temp file from device
            ssh.exec_command(f"rm {remote_tmp_path}")
            
            # enumerate the DB files in the data directories
            db_log = enumerate_db(local_path, path)
            # extract plists from the DB files
            db_extract_plists(local_path, db_log)

            print(f"    [*] Searching for embedded plists")
            parse_plists(local_path, path)
            print(f"    [*] Searching for database files")


            
    except Exception as e:
        print(f" [!] Extraction failed: {e}")
    finally:
        ssh.close()

def parse_plists(output_dir, path):
    local_files = os.path.join(output_dir, path.lstrip('/'))
    log_file = os.path.join(output_dir, "plist_files.txt")
    
    for root, dirs, files in os.walk(local_files):
        for file in files:
            file_path = os.path.join(root, file)
            is_plist = file.endswith('.plist')
            
            if not is_plist:
                try:
                    with open(file_path, 'rb') as f:
                        # look for magic bytes at the start of the file to define a binary plist or xml plist
                        header = f.read(8)
                        if header.startswith(b'bplist') or header.startswith(b'<?xml'):
                            try:
                                with open(file_path, 'rb') as f:
                                    data = plistlib.load(f)
                                # some files might match the magic bytes, but are not plists. Attempting to dump the plist iwll determine if its actually a plist.     
                                plistlib.dumps(data, fmt=plistlib.FMT_XML)    
                                is_plist = True
                            except Exception:
                                is_plist = False  
                except Exception:
                    continue

            if is_plist:
                try:
                    # open the log_file in 'append' mode and add the file_path for the plist
                    with open(log_file, "a", encoding="utf-8") as f_log:
                        f_log.write(file_path + "\n")
                except Exception as log_err:
                    print(f"    [!] Failed to log {file}: {log_err}")
                try:
                    extract_embedded_plists(file_path,log_file)
                    convert_plistXML(file_path)
                except Exception as conv_err:
                    print(f"    [!] Failed to convert:\n        {file}\n        {conv_err}")
    print(f"    [+] plists converted to XML")   
    print(f"        [+] full list of plists saved to: {log_file}")

def convert_plistXML(file_path):
    """
    Converts binary plists to XML, handling special Apple UID types 
    found in NSKeyedArchiver plists.
    """
    def patch_uid(obj):
        """Recursively convert plistlib.UID objects into standard integers."""
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

def extract_embedded_plists(file_path, log_file):
    BPLIST_MAGIC = b'bplist00'
    
    def patch_uid(obj):
        if isinstance(obj, dict):
            return {k: patch_uid(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [patch_uid(x) for x in obj]
        elif hasattr(obj, 'data') and 'UID' in str(type(obj)):
            return obj.data
        return obj

    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        matches = [m.start() for m in re.finditer(BPLIST_MAGIC, content)]
        if not matches or (len(matches) == 1 and matches[0] == 0):
            return
        
        embedded_count = 0
        for start_index in matches:
            if start_index == 0: 
                continue
                
            embedded_count += 1
            sub_data = content[start_index:]
            
            try:
                # Load the raw sub-data
                plist_data = plistlib.loads(sub_data)
                # Patch any UIDs found in the embedded plist
                patched_data = patch_uid(plist_data)
                
                out_name = f"{file_path}_embedded_{embedded_count}.plist"
                with open(out_name, 'wb') as out_f:
                    plistlib.dump(patched_data, out_f, fmt=plistlib.FMT_XML)
                
                try:
                    with open(log_file, "a", encoding="utf-8") as f_log:
                        f_log.write(out_name + "\n")
                    # Optional: Comment out the line below to reduce console noise
                    # print(f"    [+] Extracted embedded: {os.path.basename(out_name)}")
                except Exception as log_err:
                    print(f"    [!] Failed to log {os.path.basename(out_name)}: {log_err}") 
            except:
                continue
    except:
        pass

def enumerate_db(output_dir, path):
    local_files = os.path.join(output_dir, path.lstrip('/'))
    # create a log in the output directory
    log_file = os.path.join(output_dir, "DB_files.txt")
    
    # 'walk' through the extracted files
    for root, dirs, files in os.walk(local_files):
        for file in files:
            file_path = os.path.join(root, file)
            is_db = file.lower().endswith(('.db', '.sqlite', '.sqlite3'))
            

            if not is_db:
                try:
                    with open(file_path, 'rb') as f:
                        # check the file header
                        header = f.read(16)
                        if header.startswith(b'SQLite format 3'):
                            is_db = True
                except Exception:
                    pass # do nothing because its not a db
                try:
                    file_type_checker = magic.Magic()
                    # check the file description
                    file_description = file_type_checker.from_file(file_path)
                
                    if 'SQLite 3.x database' in file_description:
                        is_db = True
                except (OSError, PermissionError):
                    # Skip files we can't access
                    continue

            if is_db:
                try:
                    # open the log_file in 'append' mode and add the file_path for the plist
                    db_path = os.path.relpath(file_path, output_dir)
                    with open(log_file, "a", encoding="utf-8") as f_log:
                        f_log.write(db_path + "\n")
                except Exception as log_err:
                    print(f"         [!] Failed to log {file}: {log_err}")
    print(f"         [+] DB files logged to: {log_file}")
    return log_file

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
        print(f"         [+] Extracted plists from DB to: {new_folder}")

def enumerate_android(package_name, output_path):
    print(f"    [*] Targeting Android for package: {package_name}")
    
    # Define the absolute internal path and the external data path
    search_roots = [
        f"/data/user/0/{package_name}",
        f"/storage/emulated/0/Android/data/{package_name}"
    ]
    
    for remote_path in search_roots:
        # Check if the directory exists
        check_cmd = ["adb", "shell", f"su -c 'ls -d {remote_path}'"]
        
        try:
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            # If this works we have root access and can pull the files
            if result.returncode == 0:
                found_path = result.stdout.strip()
                print(f"    [+] Found path: {found_path}")
                
                # Determine subfolder label (data directory vs external storage)
                label = "data" if "/data/user/0" in found_path else "storage"
                android_out = os.path.join(output_path, "Android")
                
                os.makedirs(android_out, exist_ok=True)
                extract_android_files(found_path, label, android_out)
            # else try to pull external storage with standard user permissions
            else:
                print(f"[!] Path not found or inaccessible: {remote_path}")
                print("    [*] Trying without root access...")

                if "emulated" in remote_path:
                    check_cmd_no_root = ["adb", "shell", f"ls -d {remote_path}"]
                    result = subprocess.run(check_cmd_no_root, capture_output=True, text=True)
                    if result.returncode == 0:
                        extract_android_files(remote_path, label, android_out)
                        continue
                
                print(f"[-] Path not found or inaccessible: {remote_path}")
                
        except Exception as e:
            print(f"[!] ADB Error: {e}")

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
        print(f"    [+] Extraction successful: {output_path}")
        local_cleanup = ["rm", local_tar_path]
        subprocess.run(local_cleanup)
        print(f"    [*] Looking for DB files")
        enumerate_db(output_path, remote_path)
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
            print(f"[!] Error: {e}")
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

def interactive_session():
    header = r"""
    -------------------------------------------
      __  __  ____  ____  _____ _      ______ 
     |  \/  |/ __ \|  _ \|_   _| |    |  ____|
     | \  / | |  | | |_) | | | | |    | |__   
     | |\/| | |  | |  _ <  | | | |    |  __|  
     | |  | | |__| | |_) |_| |_| |____| |____ 
     |_|  |_|\____/|____/|_____|______|______|
            > MOBILE_DATA_EXTRACTOR_v1 <
    -------------------------------------------
    """
    print(header)
    
    # 1. Platform
    p_choice = input("What platform [1. Android, 2. iOS]: ").strip()
    is_ios = (p_choice == "2")
    
    # 2. Config & iOS Display
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

    # 5. Output
    default_out = os.getcwd()
    output_path = input(f"\nOutput directory [{default_out}]: ").strip() or default_out
    output_path = os.path.abspath(output_path)

    # 6. Run
    print(f"\n    [*] Starting extraction for {package_to_test}...")
    if is_ios:
        enumerate_ios(package_to_test, output_path, ip, port, user, password)
    else:
        enumerate_android(package_to_test, output_path)
    footer = r"""
    -------------------------------------------
    Done!
    -------------------------------------------
    """
    print 

if __name__ == "__main__":
    try:
        interactive_session()
    except KeyboardInterrupt:
        print("\n[!] User aborted.")
        sys.exit(0)