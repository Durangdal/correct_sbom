
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
        log(f"  > [S1] SBOM 저장됨 → {os.path.basename(filename)}")
    except Exception as e:
        log(f"  > [S1] SBOM 저장 실패: {e}")

def calculate_file_hash(file_path, algorithm='sha256'):
    """파일의 해시값을 계산 (Script 1)"""
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b''):
                hasher.update(chunk)
        return f"{algorithm}:{hasher.hexdigest()}"
    except Exception:
        return ""

def get_file_version_info(file_path):
    """Windows PE 파일에서 버전 문자열을 추출 (Script 1)"""
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
            # [수정] Windows/Linux 경로 호환성
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

# --- [Script 2 기능 추가] ---
def get_pkg_info(path):
    """(Script 2) Debian/Ubuntu 환경에서 dpkg 패키지 정보를 조회합니다."""
    # [수정] Windows에서는 이 기능이 작동하지 않도록 보호
    if platform.system() != "Linux" or not which("dpkg"):
        return None, None, None
    try:
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
                 # [수정] Script 1의 Windows 기반을 유지하기 위해 Windows 호환 코드 사용
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

        # 인터프리터 감지 (Windows 실행 파일명 포함)
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
# --- [Script 2 기능 추가 완료] ---


# --- Script 1의 Syft 및 SBOM 헬퍼 (일부 수정) ---
def get_app_internal_libs(exe_name, pid, output_dir, proc_cmdline):
    """(Script 1) 애플리케이션 내부 의존성 수집 (Syft 경로 스캔)"""
    script_path = None
    for arg in proc_cmdline:
        if arg.lower().endswith(('.py', '.js', '.jar', '.war')):
            if os.path.exists(arg):
                script_path = arg
                break
    
    if not script_path:
        log("  > [S1] 내부 스캔: Syft 분석을 위한 스크립트/앱 경로를 명령줄에서 찾을 수 없습니다.")
        return None

    # [수정] Windows 호환 (.exe)
    if not which("syft") and not which("syft.exe"):
        log("  > [S1] Syft 미설치. 내부 의존성 스캔 생략.")
        return None
        
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
             log(f"  > [S1] Syft 내부 스캔: {exe_name}에서 애플리케이션 패키지 미발견."); return None
             
        with open(out_file, "w", encoding="utf-8") as fout: fout.write(result.stdout)
        log(f"  > [S1] Syft 내부 SBOM 생성됨 → {os.path.basename(out_file)}")
        return out_file
        
    except subprocess.CalledProcessError as e:
        log(f"  > [S1] Syft 내부 스캔 실패: {e.stderr.strip()[:100]}...")
    except Exception as e:
        log(f"  > [S1] Syft 내부 스캔 실패: {e}")
    return None

def get_process_context(proc):
    """(Script 1) 프로세스의 명령줄 인자와 환경 변수를 수집"""
    context = {}
    try:
        context["command_line"] = " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied): context["command_line"] = "N/A"
        
    # [수정] Windows/Linux 공통 환경 변수
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
    """(Script 1) Syft를 사용하여 정적 SBOM을 생성 (Script 2의 호환성 로직 추가)"""
    if not which("syft") and not which("syft.exe"):
        log(f"  > [S1] syft 미설치: {exe_file} static SBOM 생략"); return None
    
    out_file_name = f"static_sbom_{os.path.basename(exe_file)}_{pid}.json"
    out_file = os.path.join(output_dir, out_file_name)
    
    # [수정] Script 2의 'scan'/'packages' 호환성 로직 적용
    try:
        # 1. 'scan' (신규) 시도
        command = ["syft", "scan", f"file:{exe_file}", "-o", "cyclonedx-json"]
        result = subprocess.run(
            command, capture_output=True, text=True, 
            encoding="utf-8", timeout=120, check=True, shell=(os.name == 'nt')
        )
    except subprocess.CalledProcessError as e:
        if "unknown command" in e.stderr:
            # 2. 'packages' (구) 시도
            log("  > [S2-Fix] 'syft scan' 실패. 'syft packages'로 재시도...")
            try:
                command = ["syft", "packages", f"file:{exe_file}", "-o", "cyclonedx-json"]
                result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=120, check=True, shell=(os.name == 'nt'))
            except Exception as e2:
                log(f"  > [S1-Fix] syft (packages) 재시도 실패: {e2}"); return None
        else:
            log(f"  > [S1] syft (scan) 실행 실패: {e.stderr.strip()[:100]}..."); return None
    except Exception as e:
         log(f"  > [S1] syft (scan) 실행 실패: {e}"); return None

    # 성공 시 파일 저장
    with open(out_file, "w", encoding="utf-8") as fout: fout.write(result.stdout)
    log(f"  > [S1] Syft Static SBOM 생성됨 → {os.path.basename(out_file)}")
    return out_file


def create_cyclonedx_sbom_v1(exe_name, pid, libs_info, runtime=True):
    """(Script 1) CycloneDX 형식의 SBOM 딕셔너리 생성 (해시/버전 포함)"""
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


# --- [신규] 통합 프로세스 핸들러 ---
def process_pid_unified(pid, exe_name_raw, exe_file, proc_cmdline_list):
    """
    Script 1의 'main' 루프가 호출할 통합 처리 함수.
    Script 1의 기능과 Script 2의 상세 정보 수집 기능을 모두 수행합니다.
    """
    
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
    
    # 2. 런타임 환경 컨텍스트 저장 (Script 1, 기능 #3)
    context_data = get_process_context(proc)
    save_context(context_data, output_dir, pid)
    
    # 3. 상세 프로세스 정보 저장 (Script 2, 기능 추가)
    process_info = get_process_info(pid)
    if process_info:
        try:
            info_file = os.path.join(output_dir, f"process_info_ext_{pid}.json")
            with open(info_file, "w", encoding="utf-8") as f:
                json.dump(process_info, f, indent=2, ensure_ascii=False)
            log(f"  > [S2] 상세 정보 저장됨 → {os.path.basename(info_file)}")
        except Exception as e:
            log(f"  > [S2] 상세 정보 저장 실패: {e}")

    # 4. OS 수준 런타임 SBOM 생성 (Script 1, 기능 #4 - 해시/버전 포함)
    libs_info = get_loaded_libs_v1(pid)
    runtime_sbom_os = create_cyclonedx_sbom_v1(exe_name_raw, pid, libs_info, runtime=True)
    runtime_output_file = os.path.join(output_dir, f"runtime_sbom_os_libs_{pid}.json")
    save_sbom(runtime_sbom_os, runtime_output_file)

    # 5. 애플리케이션 내부 의존성 SBOM 생성 (Script 1, 기능 #5)
    get_app_internal_libs(exe_name_raw, pid, output_dir, proc_cmdline_list)
    
    # 6. Static SBOM 생성 (Script 1, 기능 #6 - Script 2 로직으로 개선됨)
    if exe_file:
        run_syft_v1_static(exe_file, pid, output_dir)
    
    log(f"  > PID {pid} ({exe_name_raw}) 처리 완료.")


# --- 메인 루프 (Script 1의 psutil 폴링 방식) ---
def main():
    log(f"🏁 개별 프로세스 SBOM 감시 시작 (psutil 폴링, Windows 호환)")
    
    # 프로그램 시작 시 존재하는 모든 PID를 '이미 본 것'으로 처리
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
    # [수정] eBPF/데몬화 로직을 모두 제거하고 Script 1의 'main'을 직접 실행
    try:
        main()
    except KeyboardInterrupt:
        log("프로그램 종료 요청 (Ctrl+C).")
        sys.exit(0)
    except Exception as e:
        log(f"치명적인 오류 발생: {e}")
        sys.exit(1)
