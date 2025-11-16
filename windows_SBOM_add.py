#sbom_logs 폴더 생성
#그 아래 6가지의 파일 생성
#1. runtime_context_1234.json        	| 단순 JSON	
#- 실행 명령어, 환경 변수 저장파일
#2. process_info_ext_1234.json    	    | 단순 JSON	
#- 메모리 피크, 네트워크 IO, Python/Java 라이브러리 저장 파일
#3. runtime_sbom_os_libs_1234.json	    | CycloneDX	
#- OS 라이브러리 (.dll) + 해시/버전 저장 파일
#4. internal_sbom_app_libs_...json 	    | CycloneDX	
#- 앱 라이브러리 (예: requests, numpy)
#5. static_sbom_python.exe_1234.json	| CycloneDX	
#- 실행 파일 자체 (예: python.exe)의 정적 분석
#6. sbom_output.json
#- Colab연동, AI 학습을 위한 통합 목록, 스크립트 실행 종료시 생성(불완전한 데이터 및 비효율적인 측면을 고려해 종료시 파일 생성)

#!/usr/bin/env python3
import os
import sys
import json
import time
import psutil
import subprocess
import re
import platform
import threading
from datetime import datetime, timezone
from shutil import which
from itertools import count
import hashlib

# --- Windows용 pefile 임포트 시도 (Script 1) ---
try:
    import pefile
except ImportError:
    pefile = None
    if os.name == 'nt':
        print("Warning: 'pefile' is not installed. File version information will be limited on Windows.")

# --- 전역 설정 (Script 1 기준) ---
BASE_DIR = os.getcwd()
SBOM_DIR = os.path.join(BASE_DIR, "sbom_logs")
os.makedirs(SBOM_DIR, exist_ok=True)
LOG_FILE = os.path.join(SBOM_DIR, "sbom_monitor.log")

# 감시 대상 실행 파일 (Script 1)
TARGET_EXECUTABLES = {
    "python", "python.exe",
    "node", "node.exe",
    "java", "java.exe",
    "nginx", "nginx.exe"
}

# (Script 1)
seen_pids = set()
folder_counter = count(1)
# (Script 2) 스레드 안전용 락
counter_lock = threading.Lock()

# --- [Colab 연동용 전역 변수 추가] ---
colab_data_lock = threading.Lock()
all_components_for_colab = []
seen_purls_for_colab = set()
# --- [Colab 추가 완료] ---


# --- 유틸리티 함수 (Script 1) ---
def log(msg):
    """콘솔 및 로그 파일에 메시지 기록"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def save_sbom(sbom, filename):
    """SBOM 딕셔너리를 지정된 파일에 저장 (Script 1)"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2, ensure_ascii=False)
        log(f"  > [S1] 상세 SBOM 저장됨 → {os.path.basename(filename)}")
    except Exception as e:
        log(f"  > [S1] 상세 SBOM 저장 실패: {e}")

# --- [Colab 연동용 함수 추가] ---
def save_colab_json(filename):
    """Colab 분석용 플랫 JSON 파일을 저장합니다."""
    global all_components_for_colab
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(all_components_for_colab, f, indent=2, ensure_ascii=False)
        log(f"✅ [Colab] AI 분석용 SBOM 저장 완료 → {filename}")
        log(f"   (총 {len(all_components_for_colab)}개 컴포넌트 저장됨)")
    except Exception as e:
        log(f"❌ [Colab] AI 분석용 SBOM 저장 실패: {e}")

def parse_syft_json_for_colab(syft_json_string):
    """(Helper) Syft JSON 출력을 파싱하여 Colab용 딕셔너리 리스트로 반환"""
    components_list = []
    if not syft_json_string:
        return components_list
    try:
        sbom_data = json.loads(syft_json_string)
        components = sbom_data.get("components", [])
        for comp in components:
            components_list.append({
                "Name": comp.get("name"),
                "Version": comp.get("version"),
                "PURL": comp.get("purl"),
                "Path": f"syft:{comp.get('type')}" # 'Path'를 'description'으로 사용
            })
    except json.JSONDecodeError:
        log("  > [Colab] Syft JSON 파싱 실패")
    return components_list
# --- [Colab 추가 완료] ---


def calculate_file_hash(file_path, algorithm='sha256'):
    """(Script 1) 파일의 해시값을 계산"""
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b''):
                hasher.update(chunk)
        return f"{algorithm}:{hasher.hexdigest()}"
    except Exception:
        return ""

def get_file_version_info(file_path):
    """(Script 1) Windows PE 파일에서 버전 문자열을 추출"""
    if pefile is None or not os.name == 'nt':
        return None
    try:
        pe = pefile.PE(file_path, fast_load=True)
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            fixed_info = pe.VS_FIXEDFILEINFO[0]
            version = '{}.{}.{}.{}'.format(
                fixed_info.FileVersionMS >> 16, fixed_info.FileVersionMS & 0xFFFF,
                fixed_info.FileVersionLS >> 16, fixed_info.FileVersionLS & 0xFFFF
            )
            return version
        return None
    except Exception:
        return None
    finally:
        if 'pe' in locals() and pe:
            pe.close()


# --- 상세 정보 수집 헬퍼 (Script 1 + Script 2 기능) ---

def get_loaded_libs_v1(pid):
    """(Script 1) 프로세스에서 로드된 공유 라이브러리 (해시, 버전 포함)"""
    libs_info = {}
    try:
        proc = psutil.Process(pid)
        for m in proc.memory_maps():
            path = getattr(m, "path", None)
            if not path or not os.path.isfile(path) or path.startswith('['):
                continue
            
            if path not in libs_info:
                file_hash = calculate_file_hash(path)
                version = get_file_version_info(path) 
                
                libs_info[path] = {
                    "version": version if version else "runtime", 
                    "hash": file_hash
                }
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        pass
    except Exception as e:
        log(f"  > [S1] get_loaded_libs_v1 오류: {e}")
    return libs_info

# --- [Script 2 기능] ---
def get_pkg_info(path):
    """(Script 2) Debian/Ubuntu 환경에서 dpkg 패키지 정보를 조회합니다."""
    if platform.system() != "Linux" or not which("dpkg"):
        return None, None, None
    try:
        # ... (Script 2의 로직) ...
        output = subprocess.check_output(['dpkg', '-S', path], stderr=subprocess.STDOUT, text=True)
        match = re.search(r'([\w\d\.\-]+):', output)
        if match:
            pkg_name = match.group(1)
            ver_output = subprocess.check_output(['dpkg', '-l', pkg_name], text=True)
            lines = ver_output.split('\n')
            if len(lines) > 5:
                ver_match = re.search(r'^\S+\s+' + re.escape(pkg_name) + r'\s+(\S+)\s+(\S+)\s+', lines[5])
                if ver_match:
                    version = ver_match.group(1)
                    purl = f"pkg:deb/ubuntu/{pkg_name}@{version}"
                    return pkg_name, version, purl
    except Exception:
        pass
    return None, None, None

def get_pip_libs(pid):
    """(Script 2) Python 프로세스에서 로드된 라이브러리(.so, .pyd)를 추측합니다."""
    libs = []
    try:
        p = psutil.Process(pid)
        for lib in p.memory_maps():
            path_lower = lib.path.lower()
            if ('site-packages' in path_lower or 'dist-packages' in path_lower) and \
               (path_lower.endswith('.so') or path_lower.endswith('.pyd')):
                
                try:
                    parts = re.split(r'[\\/]', path_lower) # Windows/Linux 경로 구분자
                    pkg_dir_index = -1
                    if 'dist-packages' in parts: pkg_dir_index = parts.index('dist-packages')
                    elif 'site-packages' in parts: pkg_dir_index = parts.index('site-packages')
                        
                    if pkg_dir_index != -1 and pkg_dir_index + 1 < len(parts):
                        lib_name = parts[pkg_dir_index + 1].split('.')[0]
                    else: continue
                except ValueError:
                    lib_name = os.path.basename(lib.path).split('.')[0]

                if lib_name and lib_name not in [l['Name'] for l in libs]:
                    libs.append({'Name': lib_name, 'Path': lib.path})
    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
    return libs

def get_java_libs(pid):
    """(Script 2) Java 프로세스에서 열린 .jar 파일 목록을 가져옵니다."""
    libs = []
    try:
        p = psutil.Process(pid)
        for f in p.open_files():
            if f.path.endswith('.jar'):
                lib_name = os.path.basename(f.path)
                if lib_name not in [l['Name'] for l in libs]:
                    libs.append({'Name': lib_name, 'Path': f.path})
    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
    return libs

def get_process_info(pid: int) -> dict:
    """(Script 2) 단일 PID에 대해 상세 정보를 수집합니다. (Windows 호환)"""
    try:
        p = psutil.Process(pid)
        name = p.name()
        path = p.exe()
        threads = p.num_threads()
        status = p.status()

        memory_percent = p.memory_percent()
        memory_peak_kb = 0
        try:
            if platform.system() == "Linux":
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("VmPeak:"):
                            memory_peak_kb = int(line.split()[1]); break
            elif os.name == 'nt':
                 memory_peak_bytes = p.memory_info().peak_wset
                 memory_peak_kb = memory_peak_bytes / 1024
        except Exception: pass
        
        try:
            net_io = p.net_io_counters()
            net_io_dict = net_io._asdict()
        except Exception: net_io_dict = {}

        base_info = {
            'PID': pid, 'Name': name, 'Path': path,
            'Threads': threads, 'Status': status,
            'MemoryPercent': memory_percent, 'MemoryPeakKB': memory_peak_kb,
            'NetIOCounters': net_io_dict
        }

        name_lower = name.lower()
        if name_lower in ['python', 'python.exe', 'python3', 'java', 'java.exe', 'node', 'node.exe']:
            libs = []
            if name_lower.startswith('python'): libs = get_pip_libs(pid)
            elif name_lower.startswith('java'): libs = get_java_libs(pid)
            if libs: base_info['Libraries'] = libs
        
        elif platform.system() == "Linux":
            pkg_name, version, purl = get_pkg_info(path)
            if pkg_name:
                base_info['Package'] = pkg_name
                base_info['Version'] = version
                base_info['PURL'] = purl
                
        return base_info

    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        pass
    return None
# --- [Script 2 기능 완료] ---


# --- Script 1의 Syft 및 SBOM 헬퍼 (Colab 연동을 위해 수정됨) ---

def get_app_internal_libs(exe_name, pid, output_dir, proc_cmdline):
    """
    (Script 1) 애플리케이션 내부 의존성 수집 (Syft 경로 스캔)
    [수정] Colab 분석을 위해 Syft JSON 출력 문자열도 반환합니다.
    """
    script_path = None
    for arg in proc_cmdline:
        if arg.lower().endswith(('.py', '.js', '.jar', '.war')):
            if os.path.exists(arg):
                script_path = arg
                break
    
    if not script_path:
        log("  > [S1] 내부 스캔: Syft 분석을 위한 스크립트/앱 경로를 명령줄에서 찾을 수 없습니다.")
        return None, None # out_file, json_content

    if not which("syft") and not which("syft.exe"):
        log("  > [S1] Syft 미설치. 내부 의존성 스캔 생략.")
        return None, None
        
    base_name = exe_name.split('.')[0]
    out_file_name = f"internal_sbom_app_libs_{base_name}_{pid}.json"
    out_file = os.path.join(output_dir, out_file_name)
    
    try:
        command = ["syft", script_path, "-o", "cyclonedx-json"]
        log(f"  > [S1] Syft 내부 스캔 시도: 경로 분석 ({script_path})")
        
        result = subprocess.run(
            command, capture_output=True, text=True, 
            encoding="utf-8", timeout=180, check=True,
            shell=(os.name == 'nt') # Windows 호환성
        )
        
        if "No packages were found" in result.stderr or not result.stdout.strip():
             log(f"  > [S1] Syft 내부 스캔: {exe_name}에서 애플리케이션 패키지 미발견."); return None, None
             
        # [S1] 원본 기능: 파일 저장
        with open(out_file, "w", encoding="utf-8") as fout: fout.write(result.stdout)
        log(f"  > [S1] Syft 내부 SBOM 생성됨 → {os.path.basename(out_file)}")
        
        # [Colab] 추가 기능: JSON 문자열 반환
        return out_file, result.stdout
        
    except subprocess.CalledProcessError as e:
        log(f"  > [S1] Syft 내부 스캔 실패: {e.stderr.strip()[:100]}...")
    except Exception as e:
        log(f"  > [S1] Syft 내부 스캔 실패: {e}")
    return None, None

def get_process_context(proc):
    """(Script 1) 프로세스의 명령줄 인자와 환경 변수를 수집"""
    context = {}
    try:
        context["command_line"] = " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied): context["command_line"] = "N/A"
        
    env_vars_to_collect = ["PATH", "JAVA_HOME", "PYTHONPATH", "NODE_PATH", "CLASSPATH", "LD_LIBRARY_PATH", "USER", "HOME", "SystemRoot", "ProgramFiles"]
    env_data = {}
    try:
        process_env = proc.environ() 
        for key in env_vars_to_collect:
            if key in process_env: env_data[key] = process_env[key]
        context["environment_variables"] = env_data
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        context["environment_variables"] = {"Note": "Access Denied to environment variables."}
    return context

def save_context(context_data, output_dir, pid):
    """(Script 1) 수집된 환경 컨텍스트를 별도 JSON 파일로 저장"""
    context_file = os.path.join(output_dir, f"runtime_context_{pid}.json")
    try:
        with open(context_file, "w", encoding="utf-8") as f:
            json.dump(context_data, f, indent=2, ensure_ascii=False)
        log(f"  > [S1] 런타임 컨텍스트 저장됨 → {os.path.basename(context_file)}")
    except Exception as e:
        log(f"  > [S1] 컨텍스트 저장 실패: {e}")

def run_syft_v1_static(exe_file, pid, output_dir):
    """
    (Script 1) Syft를 사용하여 정적 SBOM을 생성 (Script 2의 호환성 로직 추가)
    [수정] Colab 분석을 위해 Syft JSON 출력 문자열도 반환합니다.
    """
    if not which("syft") and not which("syft.exe"):
        log(f"  > [S1] syft 미설치: {exe_file} static SBOM 생략"); return None, None
    
    out_file_name = f"static_sbom_{os.path.basename(exe_file)}_{pid}.json"
    out_file = os.path.join(output_dir, out_file_name)
    
    json_content = None
    try:
        # 1. 'scan' (신규) 시도
        command = ["syft", "scan", f"file:{exe_file}", "-o", "cyclonedx-json"]
        result = subprocess.run(
            command, capture_output=True, text=True, 
            encoding="utf-8", timeout=120, check=True, shell=(os.name == 'nt')
        )
        json_content = result.stdout
    except subprocess.CalledProcessError as e:
        if "unknown command" in e.stderr:
            # 2. 'packages' (구) 시도
            log("  > [S2-Fix] 'syft scan' 실패. 'syft packages'로 재시도...")
            try:
                command = ["syft", "packages", f"file:{exe_file}", "-o", "cyclonedx-json"]
                result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=120, check=True, shell=(os.name == 'nt'))
                json_content = result.stdout
            except Exception as e2:
                log(f"  > [S1-Fix] syft (packages) 재시도 실패: {e2}"); return None, None
        else:
            log(f"  > [S1] syft (scan) 실행 실패: {e.stderr.strip()[:100]}..."); return None, None
    except Exception as e:
         log(f"  > [S1] syft (scan) 실행 실패: {e}"); return None, None

    # 성공 시 파일 저장
    with open(out_file, "w", encoding="utf-8") as fout: fout.write(json_content)
    log(f"  > [S1] Syft Static SBOM 생성됨 → {os.path.basename(out_file)}")
    
    return out_file, json_content # [Colab] JSON 문자열 반환


def create_cyclonedx_sbom_v1(exe_name, pid, libs_info, runtime=True):
    """(Script 1) CycloneDX 형식의 SBOM 딕셔너리 생성 (해시/버전 포함)"""
    # ... (Script 1의 원본 함수, 수정 없음) ...
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": exe_name, "version": "runtime" if runtime else "static"}
        },
        "components": []
    }
    for lib_path, info in libs_info.items(): # info = {"version": ..., "hash": ...}
        lib_name = os.path.basename(lib_path)
        cleaned_path = lib_path.replace(":", "").replace("\\", "/")
        purl = f"pkg:generic/{lib_name}?file_path={cleaned_path}"
        
        comp = {
            "type": "library", "name": lib_name,
            "version": info.get("version", "runtime"), "purl": purl,
        }
        
        file_hash = info.get("hash")
        if file_hash and file_hash.startswith("sha256:"):
             comp["hashes"] = [{"alg": "SHA-256", "content": file_hash.split(':')[1]}]
             
        sbom["components"].append(comp)
    return sbom


# --- [통합] 프로세스 핸들러 (Colab 연동 기능 포함) ---
def process_pid_unified(pid, exe_name_raw, exe_file, proc_cmdline_list):
    """
    Script 1의 'main' 루프가 호출할 통합 처리 함수.
    Script 1의 기능 + Script 2의 상세 정보 + Colab용 JSON 데이터 생성을 모두 수행합니다.
    """
    global all_components_for_colab, seen_purls_for_colab, colab_data_lock
    
    # 1. 폴더 생성 (Script 1)
    current_time = datetime.now()
    timestamp_str = current_time.strftime("%Y%m%dT%H%M%S")
    with counter_lock:
        counter = next(folder_counter)
    base_name = exe_name_raw.split('.')[0].replace('/', '_').replace(' ', '_').replace('.', '_')
    new_folder_name = f"{base_name}_{timestamp_str}_{counter:04d}"
    output_dir = os.path.join(SBOM_DIR, new_folder_name)
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        log(f"✅ [{current_time.strftime('%H:%M:%S')}] 실행 감지: {exe_name_raw} (PID={pid}). 폴더: {new_folder_name}")
    except Exception as e:
        log(f"[!] 폴더 생성 실패: {e}"); return
    
    # psutil 객체 생성 (Script 1의 'proc' 객체)
    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        log(f"  > PID {pid}의 psutil 객체 생성 실패. 처리를 중단합니다."); return
    
    # --- [Colab용] 핵심 동적 데이터 수집 ---
    process_info = get_process_info(pid) # (Script 2)
    colab_mem_percent = 0.0
    colab_net_conns = 0
    if process_info:
        colab_mem_percent = process_info.get('MemoryPercent', 0.0)
    try:
        # [Colab용] NetConnections는 proc.connections()의 '개수'를 사용
        colab_net_conns = len(proc.connections())
    except Exception:
        colab_net_conns = 0 # 권한 문제 등으로 실패 시 0
    # --- [Colab용 수집 완료] ---

    # 2. 런타임 환경 컨텍스트 저장 (Script 1, 기능 #3)
    context_data = get_process_context(proc)
    save_context(context_data, output_dir, pid)
    
    # 3. 상세 프로세스 정보 저장 (Script 2, 기능 추가)
    if process_info:
        try:
            info_file = os.path.join(output_dir, f"process_info_ext_{pid}.json")
            with open(info_file, "w", encoding="utf-8") as f:
                json.dump(process_info, f, indent=2, ensure_ascii=False)
            log(f"  > [S2] 상세 정보 저장됨 → {os.path.basename(info_file)}")
        except Exception as e:
            log(f"  > [S2] 상세 정보 저장 실패: {e}")

    # 4. OS 수준 런타임 SBOM 생성 (Script 1, 기능 #4)
    libs_info = get_loaded_libs_v1(pid)
    runtime_sbom_os = create_cyclonedx_sbom_v1(exe_name_raw, pid, libs_info, runtime=True)
    runtime_output_file = os.path.join(output_dir, f"runtime_sbom_os_libs_{pid}.json")
    save_sbom(runtime_sbom_os, runtime_output_file)
    
    # [Colab] 데이터 추가 (OS Libs)
    for lib_path, info in libs_info.items():
        name = os.path.basename(lib_path)
        purl = f"pkg:generic/{name}?file_path={lib_path.replace(':', '').replace(os.sep, '/')}"
        with colab_data_lock:
            if purl not in seen_purls_for_colab:
                seen_purls_for_colab.add(purl)
                all_components_for_colab.append({
                    "Name": name,
                    "Version": info.get("version", "runtime"),
                    "PURL": purl,
                    "PID": pid,
                    "Path": lib_path, # Colab이 'Path' -> 'description'으로 사용
                    "MemoryPercent": colab_mem_percent,
                    "NetConnections": colab_net_conns
                })

    # 5. 애플리케이션 내부 의존성 SBOM 생성 (Script 1, 기능 #5)
    app_sbom_file, app_sbom_content = get_app_internal_libs(exe_name_raw, pid, output_dir, proc_cmdline_list)
    
    # [Colab] 데이터 추가 (App Libs)
    if app_sbom_content:
        colab_app_libs = parse_syft_json_for_colab(app_sbom_content)
        with colab_data_lock:
            for lib in colab_app_libs:
                if lib.get("PURL") and lib["PURL"] not in seen_purls_for_colab:
                    seen_purls_for_colab.add(lib["PURL"])
                    lib.update({
                        "PID": pid,
                        "MemoryPercent": colab_mem_percent,
                        "NetConnections": colab_net_conns
                    })
                    all_components_for_colab.append(lib)

    # 6. Static SBOM 생성 (Script 1, 기능 #6)
    static_sbom_file, static_sbom_content = (None, None)
    if exe_file:
        static_sbom_file, static_sbom_content = run_syft_v1_static(exe_file, pid, output_dir)

    # [Colab] 데이터 추가 (Static Libs)
    if static_sbom_content:
        colab_static_libs = parse_syft_json_for_colab(static_sbom_content)
        with colab_data_lock:
            for lib in colab_static_libs:
                if lib.get("PURL") and lib["PURL"] not in seen_purls_for_colab:
                    seen_purls_for_colab.add(lib["PURL"])
                    lib.update({
                        "PID": pid,
                        "MemoryPercent": colab_mem_percent,
                        "NetConnections": colab_net_conns
                    })
                    all_components_for_colab.append(lib)

    # [Colab] 데이터 추가 (Script 2 - Python/Java Libs)
    if process_info and process_info.get('Libraries'):
        with colab_data_lock:
            for lib in process_info['Libraries']:
                name = lib.get('Name')
                path = lib.get('Path')
                purl = f"pkg:generic/{name}?path={path.replace(':', '').replace(os.sep, '/')}" # 단순 PURL 생성
                if name.lower().startswith('python'):
                    purl = f"pkg:pypi/{name}" # Pypi
                elif name.lower().endswith('.jar'):
                    purl = f"pkg:maven/unknown/{name.replace('.jar','')}" # Maven
                
                if purl not in seen_purls_for_colab:
                    seen_purls_for_colab.add(purl)
                    all_components_for_colab.append({
                        "Name": name,
                        "Version": "runtime",
                        "PURL": purl,
                        "PID": pid,
                        "Path": path,
                        "MemoryPercent": colab_mem_percent,
                        "NetConnections": colab_net_conns
                    })

    log(f"  > PID {pid} ({exe_name_raw}) 처리 완료. [Colab] 총 {len(all_components_for_colab)}개 컴포넌트 누적.")


# --- 메인 루프 (Script 1의 psutil 폴링 방식) ---
def main():
    log(f"🏁 개별 프로세스 SBOM 감시 시작 (psutil 폴링, Windows 호환)")
    log(f"   (종료 시 '{os.path.join(SBOM_DIR, 'sbom_output.json')}' 파일 생성)")
    
    log("... 현재 실행 중인 프로세스 목록을 스캔합니다 ...")
    try:
        for proc in psutil.process_iter(['pid']):
            seen_pids.add(proc.info['pid'])
        log(f"... {len(seen_pids)}개의 기존 프로세스를 감시에서 제외합니다 ...")
    except Exception as e:
        log(f"기존 프로세스 스캔 중 오류: {e}")

    while True:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
            try:
                pid = proc.info["pid"]
                exe_name_raw = proc.info.get("name") or ""
                exe_name = exe_name_raw.lower()
                exe_file = proc.info.get("exe") or ""
                proc_cmdline_list = proc.info.get("cmdline") or []

                if pid in seen_pids or exe_name not in TARGET_EXECUTABLES:
                    continue

                seen_pids.add(pid)
                
                # [수정] 모든 작업을 'process_pid_unified' 함수로 넘기고
                # 메인 루프가 막히지 않도록 스레드로 실행
                t = threading.Thread(target=process_pid_unified, args=(pid, exe_name_raw, exe_file, proc_cmdline_list))
                t.start()

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log(f"메인 루프 예외 발생: {e}")
        
        time.sleep(1) # 1초 간격 폴링

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("프로그램 종료 요청 (Ctrl+C). Colab용 최종 파일 저장을 시도합니다...")
        # [Colab] 종료 시 최종 파일 저장
        output_file = os.path.join(SBOM_DIR, "sbom_output.json")
        save_colab_json(output_file)
        sys.exit(0)
    except Exception as e:
        log(f"치명적인 오류 발생: {e}")
        # [Colab] 오류 발생 시에도 저장 시도
        output_file = os.path.join(SBOM_DIR, "sbom_output.json")
        if not os.path.exists(output_file) and all_components_for_colab:
             log("오류 종료 전, Colab 파일 저장을 시도합니다...")
             save_colab_json(output_file)
        sys.exit(1)
