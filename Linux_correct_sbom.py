#!/usr/bin/env python3
try:
    from bcc import BPF
except ImportError:
    print("bcc (eBPF) 모듈을 찾을 수 없어 임포트를 건너뜁니다.")
    BPF = None
import psutil
import json
import subprocess
import re

def get_pkg_info(path):
    try:
        output = subprocess.check_output(['dpkg', '-S', path], stderr=subprocess.STDOUT, text=True)
        match = re.search(r'([\w\d\.\-]+):', output)
        if match:
            pkg_name = match.group(1)
            ver_output = subprocess.check_output(['dpkg', '-l', pkg_name], text=True)
            ver_match = re.search(r'\s+(\S+)\s+(\S+)\s+', ver_output.split('\n')[5])
            if ver_match:
                version = ver_match.group(2)
                purl = f"pkg:deb/ubuntu/{pkg_name}@{version}"
                return pkg_name, version, purl
    except Exception as e:
        pass
    return None, None, None

def get_pip_libs(pid):
    libs = []
    try:
        p = psutil.Process(pid)
        for lib in p.memory_maps():
            if lib.path.startswith('/usr/lib/python') and lib.path.endswith('.so'):
                lib_name = lib.path.split('/')[-1].split('.')[0]
                if lib_name not in [l['Name'] for l in libs]:
                    libs.append({'Name': lib_name, 'Path': lib.path})
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return libs

def get_java_libs(pid):
    libs = []
    try:
        p = psutil.Process(pid)
        for lib in p.open_files():
            if lib.path.endswith('.jar'):
                lib_name = lib.path.split('/')[-1]
                if lib_name not in [l['Name'] for l in libs]:
                    libs.append({'Name': lib_name, 'Path': lib.path})
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return libs

def get_process_info(pid):
    try:
        p = psutil.Process(pid)
        name = p.name()
        path = p.exe()
        threads = p.num_threads()
        status = p.status()

        # --- 🔽 [수정된 부분 1] 🔽 ---
        # (신규) 실제 메모리 및 네트워크 사용량 수집
        memory_percent = p.memory_percent() # 프로세스의 메모리 사용률 (%)
        
        try:
            # p.connections()는 권한 문제(AccessDenied)가 빈번하므로 별도 try 처리
            net_connections = len(p.connections()) # 현재 네트워크 연결 수
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            net_connections = 0 # 권한 없는 경우 0
        # --- 🔼 [수정 완료 1] 🔼 ---


        if name.lower() in ['python', 'python3', 'java', 'node', 'ruby', 'perl', 'php']:
            libs = []
            if name.lower().startswith('python'):
                libs = get_pip_libs(pid)
            elif name.lower() == 'java':
                libs = get_java_libs(pid)
            
            # --- 🔽 [수정된 부분 2] 🔽 ---
            process_info = {
                'PID': pid,
                'Name': name,
                'Path': path,
                'Threads': threads,
                'Status': status,
                'MemoryPercent': memory_percent,  # (신규) 필드 추가
                'NetConnections': net_connections # (신규) 필드 추가
            }
            # --- 🔼 [수정 완료 2] 🔼 ---

            if libs:
                process_info['Libraries'] = libs
            return process_info

        else:
            pkg_name, version, purl = get_pkg_info(path)
            if pkg_name:
                
                # --- 🔽 [수정된 부분 3] 🔽 ---
                return {
                    'PID': pid,
                    'Name': name,
                    'Package': pkg_name,
                    'Version': version,
                    'PURL': purl,
                    'Path': path,
                    'Threads': threads,
                    'Status': status,
                    'MemoryPercent': memory_percent,  # (신규) 필드 추가
                    'NetConnections': net_connections # (신규) 필드 추가
                }
                # --- 🔼 [수정 완료 3] 🔼 ---
                
    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        pass
    return None

def main():
    sbom = []
    pids = [pid for pid in psutil.pids()]

    for pid in pids:
        info = get_process_info(pid)
        if info:
            sbom.append(info)

    with open('sbom_output.json', 'w') as f:
        json.dump(sbom, f, indent=4)
    print(f" SBOM 'sbom_output.json' (으)로 {len(sbom)} 개의 프로세스/라이브러리 정보를 저장했습니다.")

if __name__ == "__main__":
    main()
