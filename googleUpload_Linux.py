#!/usr/bin/env python3

# eBPF (bcc) 임포트 시도
try:
    from bcc import BPF
except ImportError:
    print("경고: bcc (eBPF) 모듈을 찾을 수 없습니다.")
    print("eBPF 기반 실행 감지 기능이 비활성화됩니다.")
    BPF = None

import ctypes as ct
import json
import os
import subprocess
import psutil
import re
import platform
import sys
import threading
import time
import zipfile
import glob
from datetime import datetime, timezone
from shutil import which, rmtree
from itertools import count

# Google Drive API 관련 임포트 (사용자 설치 필요)
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    from googleapiclient.http import MediaFileUpload
    GOOGLE_DRIVE_AVAILABLE = True
except ImportError:
    GOOGLE_DRIVE_AVAILABLE = False
    # print("경고: Google Drive API 모듈을 찾을 수 없습니다. (google-auth, google-auth-oauthlib, google-api-python-client)")
    # print("Google Drive 업로드 기능이 비활성화됩니다.")


# --- 전역 설정 및 상수 ---
BASE_OUTPUT_DIR = "/tmp/runtime_sbom_outputs"
GOOGLE_DRIVE_FOLDER_NAME = "RuntimeSBOMs" # Drive에 생성될 최상위 폴더 이름
SCOPES = ['https://www.googleapis.com/auth/drive.file']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'credentials.json'

# 순차적 번호 관리를 위한 카운터와 락
global_counter = count(1)
counter_lock = threading.Lock()


# --- Google Drive 업로드 클래스 ---
class DriveUploader:
    def __init__(self):
        self.service = None
        self.drive_folder_id = None
        self._authenticate()
        if self.service:
            self.drive_folder_id = self._get_or_create_folder(GOOGLE_DRIVE_FOLDER_NAME)

    def _authenticate(self):
        """인증 정보를 로드하거나 OAuth 2.0 흐름을 실행하여 새 토큰을 생성합니다."""
        creds = None
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        
        # 유효하지 않거나 만료된 경우 새로고침
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                print("Drive API 토큰 갱신 중...")
                creds.refresh(Request())
            else:
                if not os.path.exists(CREDENTIALS_FILE):
                    print(f"치명적 오류: Drive API 인증 파일 '{CREDENTIALS_FILE}'을(를) 찾을 수 없습니다.", file=sys.stderr)
                    return
                print("Drive API 인증 흐름 시작. 브라우저 창에서 승인하세요.")
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                    # 인증 코드를 로컬 서버를 통해 받도록 설정 (데몬 환경에서 필요)
                    creds = flow.run_local_server(port=0)
                except Exception as e:
                    print(f"Drive API 인증 실패: {e}", file=sys.stderr)
                    return

            # 새로운 토큰 저장
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())

        if creds:
            try:
                self.service = build('drive', 'v3', credentials=creds)
                print("✅ Google Drive 서비스 초기화 성공.")
            except Exception as e:
                print(f"Google Drive 서비스 빌드 실패: {e}", file=sys.stderr)

    def _get_or_create_folder(self, folder_name):
        """Google Drive에서 폴더를 찾거나 생성하고 ID를 반환합니다."""
        if not self.service:
            return None
        try:
            # 폴더 검색
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            response = self.service.files().list(q=query, spaces='drive', fields='files(id)').execute()
            files = response.get('files', [])

            if files:
                print(f"Drive 폴더 발견: '{folder_name}' ID: {files[0]['id']}")
                return files[0]['id']
            else:
                # 폴더 생성
                file_metadata = {
                    'name': folder_name,
                    'mimeType': 'application/vnd.google-apps.folder'
                }
                file = self.service.files().create(body=file_metadata, fields='id').execute()
                print(f"Drive 폴더 생성: '{folder_name}' ID: {file.get('id')}")
                return file.get('id')
        except HttpError as e:
            print(f"Google Drive 폴더 처리 오류: {e}", file=sys.stderr)
            return None

    def upload_file(self, file_path, file_name, mime_type):
        """파일을 Google Drive에 업로드합니다."""
        if not self.service or not self.drive_folder_id:
            print(f"[!] Drive 업로드 실패: 서비스 미초기화 또는 폴더 ID 없음.")
            return False

        file_metadata = {
            'name': file_name,
            'parents': [self.drive_folder_id]
        }
        media = MediaFileUpload(file_path, mimetype=mime_type, resumable=True)

        try:
            print(f"  > Drive 업로드 시작: {file_name}")
            file = self.service.files().create(body=file_metadata, media_body=media, fields='id').execute()
            print(f"  > Drive 업로드 성공! 파일 ID: {file.get('id')}")
            return True
        except HttpError as e:
            print(f"[!] Drive 업로드 오류 ({file_name}): {e}", file=sys.stderr)
            return False

# --- 디렉토리 압축 헬퍼 ---
def zip_directory(directory_path, output_zip_path):
    """지정된 디렉토리의 내용을 .zip 파일로 압축합니다."""
    try:
        with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # zipf.write(source_path, arcname) - 아카이브 내 경로 설정
                    arcname = os.path.relpath(file_path, os.path.dirname(directory_path))
                    zipf.write(file_path, arcname)
        return True
    except Exception as e:
        print(f"[!] 디렉토리 압축 실패 ({directory_path}): {e}", file=sys.stderr)
        return False


# --- 데몬화 컨텍스트 관리자 ---
class DaemonizeContext:
    def __init__(self, pid_file='/tmp/runtime_sbom_monitor.pid', stdout_file='/tmp/runtime_sbom_monitor.log', stderr_file='/tmp/runtime_sbom_monitor.log'):
        self.pid_file = pid_file
        # utf-8 인코딩 명시
        self.stdout = open(stdout_file, 'a+', encoding='utf-8')
        self.stderr = open(stderr_file, 'a+', buffering=1, encoding='utf-8')

    def __enter__(self):
        self.cleanup_pid()
        self.write_pid()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 종료 시 PID 파일 제거
        if os.path.exists(self.pid_file):
            try:
                os.remove(self.pid_file)
            except OSError as e:
                print(f"경고: PID 파일 {self.pid_file} 제거 실패: {e}", file=sys.stderr)
        self.stdout.close()
        self.stderr.close()

    def cleanup_pid(self):
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                if psutil.pid_exists(pid):
                    # 이미 실행 중인 프로세스가 있으면, 현재 프로세스 종료
                    print(f"경고: PID {pid}를 가진 모니터가 이미 실행 중입니다. (PID 파일: {self.pid_file})", file=sys.stderr)
                    print("기존 프로세스를 종료하고 다시 시도하세요.", file=sys.stderr)
                    sys.exit(1)
                os.remove(self.pid_file)
            except Exception as e:
                print(f"경고: 이전 PID 파일 처리 중 오류 발생: {e}", file=sys.stderr)
                try:
                    os.remove(self.pid_file) # 문제 발생 시에도 일단 제거 시도
                except OSError:
                    pass

    def write_pid(self):
        try:
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
        except IOError as e:
            print(f"치명적 오류: PID 파일 {self.pid_file} 쓰기 실패: {e}", file=sys.stderr)
            sys.exit(1)

def daemonize(context_manager, b_obj, uploader_obj): 
    # 1차 fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"1차 fork 실패: {e}\n")
        sys.exit(1)
    os.setsid() # 새 세션 리더
    # 2차 fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"2차 fork 실패: {e}\n")
        sys.exit(1)

    os.chdir("/")
    os.umask(0)
    try:
        sys.stdin.close()
    except OSError:
        pass

    with context_manager as ctx:
        os.dup2(ctx.stdout.fileno(), sys.stdout.fileno())
        os.dup2(ctx.stderr.fileno(), sys.stderr.fileno())
        # b 객체와 uploader 객체 전달
        main_loop(b_obj, uploader_obj)


# --- eBPF C 코드 (Script 1 방식) ---
bpf_program_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct {
        u32 pid;
        char comm[TASK_COMM_LEN];
        char filename[256]; // <-- 256바이트 유지
    } data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# --- 상세 정보 수집 헬퍼 (기존 기능 유지) ---
def get_pkg_info(path):
    """Debian/Ubuntu 환경에서 파일 경로로부터 dpkg 패키지 정보를 조회합니다."""
    if not which("dpkg"):
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
    """실행 중인 Python 프로세스에서 로드된 라이브러리(.so)를 추측합니다."""
    libs = []
    try:
        p = psutil.Process(pid)
        for lib in p.memory_maps():
            if ('/usr/lib/python' in lib.path or '/usr/local/lib/python' in lib.path) and lib.path.endswith('.so'):
                parts = lib.path.split('/')
                try:
                    pkg_dir_index = -1
                    if 'dist-packages' in parts:
                        pkg_dir_index = parts.index('dist-packages')
                    elif 'site-packages' in parts:
                          pkg_dir_index = parts.index('site-packages')
                    
                    if pkg_dir_index != -1 and pkg_dir_index + 1 < len(parts):
                        lib_name = parts[pkg_dir_index + 1].split('.')[0]
                    else:
                        continue
                except ValueError:
                    lib_name = lib.path.split('/')[-1].split('.')[0]

                if lib_name and lib_name not in [l['Name'] for l in libs]:
                    libs.append({'Name': lib_name, 'Path': lib.path})
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return libs

def get_java_libs(pid):
    """실행 중인 Java 프로세스에서 열린 .jar 파일 목록을 가져옵니다."""
    libs = []
    try:
        p = psutil.Process(pid)
        for f in p.open_files():
            if f.path.endswith('.jar'):
                lib_name = os.path.basename(f.path)
                if lib_name not in [l['Name'] for l in libs]:
                    libs.append({'Name': lib_name, 'Path': f.path})
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return libs

def get_process_info(pid: int) -> dict:
    """단일 PID에 대해 상세 정보를 수집합니다."""
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
                            memory_peak_kb = int(line.split()[1])
                            break
        except (FileNotFoundError, ProcessLookupError, psutil.NoSuchProcess, PermissionError):
            pass
        
        try:
            net_io = p.net_io_counters()
            net_io_dict = net_io._asdict()
        except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
            net_io_dict = {}

        base_info = {
            'PID': pid,
            'Name': name,
            'Path': path,
            'Threads': threads,
            'Status': status,
            'MemoryPercent': memory_percent,
            'MemoryPeakKB': memory_peak_kb,
            'NetIOCounters': net_io_dict
        }

        # 인터프리터 감지
        if name.lower() in ['python', 'python3', 'java', 'node', 'ruby', 'perl', 'php']:
            libs = []
            if name.lower().startswith('python'):
                libs = get_pip_libs(pid)
            elif name.lower() == 'java':
                libs = get_java_libs(pid)
            
            if libs:
                base_info['Libraries'] = libs
            return base_info
        else:
            # 일반 바이너리, dpkg 정보 조회
            pkg_name, version, purl = get_pkg_info(path)
            if pkg_name:
                base_info['Package'] = pkg_name
                base_info['Version'] = version
                base_info['PURL'] = purl
            return base_info

    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        pass
    return None


# --- SBOM 및 Syft 헬퍼 ---
def new_sbom():
    """새로운 CycloneDX 1.5 SBOM 템플릿을 생성합니다."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "custom",
                    "name": "runtime-sbom-monitor",
                    "version": "2.0-with-gdrive-upload" # 버전 업데이트
                }
            ],
            "component": {
                "type": "application",
                "name": "runtime-environment",
                "properties": [
                    {"name": "host.os", "value": platform.system()},
                    {"name": "host.os_version", "value": platform.version()},
                    {"name": "host.kernel", "value": platform.release()},
                    {"name": "host.arch", "value": platform.machine()}
                ]
            },
        },
        "components": []
    }

def get_loaded_libs(pid: int) -> dict:
    """psutil memory_maps를 사용해 로드된 모든 공유 라이브러리(.so)를 스캔합니다."""
    libs_info = {}
    try:
        proc = psutil.Process(pid)
        for m in proc.memory_maps():
            path = getattr(m, "path", None)
            if not path or not os.path.isabs(path) or not os.path.isfile(path):
                continue
            if path.startswith("["):
                continue
            if '.so' in path or path.startswith('/lib/') or path.startswith('/usr/lib/'):
                 if path not in libs_info:
                     libs_info[path] = "runtime"
    except psutil.NoSuchProcess:
        # print(f"  > get_loaded_libs(pid={pid}) 스캔 실패: 프로세스가 이미 종료됨.")
        pass
    except Exception as e:
        print(f"  > get_loaded_libs(pid={pid}) 오류: {e}")
    return libs_info

def run_syft(exe_file: str, pid: int, output_dir: str):
    """Syft를 실행하여 정적 SBOM을 생성합니다."""
    if not which("syft"):
        print("[!] syft 미설치: 정적 SBOM 생략")
        return

    if not exe_file or not os.path.isabs(exe_file) or not os.path.exists(exe_file):
        print(f"[!] syft 스킵: 유효한 실행 파일 경로가 아닙니다. 경로: '{exe_file}'")
        return
    
    out_file_name = f"cyclonedx-static-sbom.json"
    out_file = os.path.join(output_dir, out_file_name)
    
    try:
        # Syft v1.0+ (syft scan file:...)
        result = subprocess.run(
            ["syft", "scan", f"file:{exe_file}", "-o", "cyclonedx-json"],
            capture_output=True,
            check=True,
            timeout=60,
            encoding="utf-8"
        )
        
        with open(out_file, "w", encoding="utf-8") as fout:
            fout.write(result.stdout)
        print(f"  > Syft 정적 SBOM 생성됨: {out_file_name}")
        
    except subprocess.CalledProcessError as e:
        # Syft < v1.0 (syft packages file:...)
        if "unknown command \"scan\"" in (e.stderr or ''):
            print("  > 'syft scan' 실패. 구버전 'syft packages'로 재시도...")
            try:
                result = subprocess.run(
                    ["syft", "packages", f"file:{exe_file}", "-o", "cyclonedx-json"],
                    capture_output=True, check=True, timeout=60, encoding="utf-8"
                )
                with open(out_file, "w", encoding="utf-8") as fout:
                    fout.write(result.stdout)
                print(f"  > Syft (구버전) 정적 SBOM 생성됨: {out_file_name}")
            except Exception as e2:
                print(f"[!] syft (구버전) 실행도 실패: {e2}")
        else:
            print(f"[!] syft 실행 실패 (종료 코드 {e.returncode}): {e.cmd}")
            syft_stderr = e.stderr.strip() if e.stderr else '표준 오류 출력 없음'
            print(f"    Syft Stderr: {syft_stderr[:500] if len(syft_stderr) > 500 else syft_stderr}")
    except FileNotFoundError:
        print("[!] syft 실행 파일을 찾을 수 없습니다. (PATH 문제)")
    except subprocess.TimeoutExpired:
        print(f"[!] syft 실행 시간 초과 (60초 초과): {exe_file}")
    except Exception as e:
        print(f"[!] syft 실행 중 예상치 못한 오류 발생: {type(e).__name__}: {e}")


# --- eBPF 초기화 ---
b = None
if BPF:
    try:
        b = BPF(text=bpf_program_code)
        syscall_fnname = b.get_syscall_fnname("execve")
        b.attach_kprobe(event=syscall_fnname, fn_name="trace_execve")
        
        print(f"eBPF 초기화: '{syscall_fnname}'에 'trace_execve' kprobe 연결 성공.")
        
    except Exception as e:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print(f"!!!!!!!!! eBPF 초기화 실패 (Script 1 방식 시도 중) !!!!!!!!!")
        print(f"오류: {e}", flush=True)
        b = None # 실패 시 명시적으로 None 설정
else:
    print("eBPF (bcc) 모듈이 없어 실행 감지를 시작할 수 없습니다.")


# --- 메인 루프 ---
def main_loop(b_instance, uploader_instance):
    if b_instance is None:
        print("eBPF가 초기화되지 않아 (b_instance is None) 메인 루프를 시작할 수 없습니다.")
        return

    os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)
    print(f"🚀 런타임 SBOM 감시 시작 (PID: {os.getpid()})")
    print(f"📄 모든 SBOM 출력은 하위 디렉토리에 저장됩니다: {BASE_OUTPUT_DIR}")
    if not GOOGLE_DRIVE_AVAILABLE or not uploader_instance.service:
        print("⚠️ Google Drive 업로드 기능이 비활성화되었습니다. (모듈 누락 또는 인증 실패)")

    # eBPF 이벤트 핸들러
    def handle_event(cpu, data, size):
        global global_counter
        
        # 1. 이벤트 데이터 파싱
        try:
            event = b_instance["events"].event(data)
            proc_name_raw = event.comm.decode("utf-8", "replace")
            exe_file = event.filename.decode("utf-8", "replace")
            pid = event.pid
        except Exception as e:
            print(f"[!] 이벤트 파싱 실패: {e}")
            return
            
        if proc_name_raw == 'syft' or proc_name_raw.startswith('python') and ('runtime_sbom_monitor' in exe_file or 'Linux_SBOM_test' in exe_file):
            return
        
        # 2. 출력 디렉토리 생성 및 번호 할당
        proc_name = proc_name_raw.replace('/', '_').replace(' ', '_').replace('.', '_')
        current_time = datetime.now()
        timestamp_str = current_time.strftime("%Y%m%d%H%M%S")

        with counter_lock:
            sequence_num = next(global_counter)
        
        event_output_dir_name = f"{proc_name}_{timestamp_str}_{sequence_num:04d}"
        event_output_dir = os.path.join(BASE_OUTPUT_DIR, event_output_dir_name)
        zip_file_path = f"{event_output_dir}.zip"

        try:
            os.makedirs(event_output_dir, exist_ok=False)
            print(f"[{current_time.strftime('%H:%M:%S')}] [실행 감지] {proc_name_raw} (PID={pid}). 출력 폴더 생성: {event_output_dir_name}")
        except FileExistsError:
            print(f"[!] 폴더 생성 충돌 감지 (무시): {event_output_dir_name}")
            return
        except Exception as e:
            print(f"[!] 폴더 생성 실패: {e}")
            return

        # 3. 런타임 SBOM 생성
        runtime_sbom = new_sbom()
        seen_purls = set()
        
        time.sleep(0.1) # 프로세스 로드 대기

        # 4. 고급 정보 수집 및 메인 컴포넌트 추가
        process_info = get_process_info(pid)
        main_component = {
            "type": "application", "name": proc_name_raw, "version": "runtime",
            "properties": [
                {"name": "file_path", "value": exe_file},
                {"name": "pid", "value": str(pid)}
            ]
        }
        
        if process_info:
            purl_val = process_info.get('PURL', f"pkg:generic/{proc_name_raw}?pid={pid}&exe={exe_file}")
            main_component['purl'] = purl_val
            main_component['version'] = process_info.get('Version', 'runtime')
            
            main_component["properties"].extend([
                {"name": "status", "value": process_info.get('Status', 'unknown')},
                {"name": "threads", "value": str(process_info.get('Threads', '0'))},
                {"name": "memoryPercent", "value": f"{process_info.get('MemoryPercent', 0):.2f}%"},
                {"name": "memoryPeakKB", "value": str(process_info.get('MemoryPeakKB', '0'))}
            ])
            
            net_io_data = process_info.get('NetIOCounters', {})
            for key, value in net_io_data.items():
                main_component["properties"].append({"name": f"netIO_{key}", "value": str(value)})

            if process_info.get('Package'):
                 main_component["properties"].append({"name": "dpkg.package", "value": process_info.get('Package')})

            # 라이브러리 추가
            if process_info.get('Libraries'):
                 for lib in process_info['Libraries']:
                    lib_name = lib.get('Name', 'unknown-lib')
                    lib_path = lib.get('Path', 'unknown-path')
                    proc_name_lower = process_info.get('Name', '').lower()
                    lib_type, purl = "library", f"pkg:generic/{lib_name}?path={lib_path}"
                    
                    if proc_name_lower.startswith('python'):
                        purl = f"pkg:pypi/{lib_name}"
                    elif proc_name_lower == 'java':
                        ver_match = re.search(r'-([\d\.]+.*?)(\.jar)', lib_name)
                        version = ver_match.group(1) if ver_match else "runtime"
                        base_name = lib_name.replace(f"-{version}", "") if ver_match else lib_name.replace(".jar", "")
                        purl = f"pkg:maven/unknown/{base_name}@{version}"

                    if purl not in seen_purls:
                        runtime_sbom["components"].append({
                            "type": lib_type, "name": lib_name, "purl": purl,
                            "properties": [{"name": "file_path", "value": lib_path}]
                        })
                        seen_purls.add(purl)

        else:
            main_component['purl'] = f"pkg:generic/{proc_name_raw}?pid={pid}&status=terminated"

        runtime_sbom["components"].append(main_component)
        seen_purls.add(main_component['purl'])

        # 로드된 공유 라이브러리(.so) 추가
        libs_info = get_loaded_libs(pid)
        for lib_path, version in libs_info.items():
            lib_name = os.path.basename(lib_path)
            purl = f"pkg:generic/{lib_name}?path={lib_path}"
            
            if purl not in seen_purls:
                runtime_sbom["components"].append({
                    "type": "library", "name": lib_name, "version": version, "purl": purl,
                    "properties": [{"name": "file_path", "value": lib_path}]
                })
                seen_purls.add(purl)

        # 5. 런타임 SBOM 저장
        runtime_sbom_file_name = f"cyclonedx-runtime-sbom.json"
        runtime_sbom_path = os.path.join(event_output_dir, runtime_sbom_file_name)
        
        try:
            with open(runtime_sbom_path, "w", encoding="utf-8") as f:
                json.dump(runtime_sbom, f, indent=2, ensure_ascii=False)
            print(f"  > 런타임 SBOM 저장 완료 ({len(runtime_sbom['components'])}개 컴포넌트): {runtime_sbom_file_name}")
        except Exception as e:
            print(f"[!] 런타임 SBOM 저장 실패: {e}")

        # 6. Syft 실행 (정적 SBOM 생성)
        run_syft(exe_file, pid, event_output_dir)

        # 7. Google Drive 업로드 로직
        if GOOGLE_DRIVE_AVAILABLE and uploader_instance.service:
            print("  > Drive 업로드를 위해 폴더 압축 시작...")
            if zip_directory(event_output_dir, zip_file_path):
                upload_success = uploader_instance.upload_file(zip_file_path, os.path.basename(zip_file_path), 'application/zip')
                
                # 8. 정리 (업로드 성공 시에만)
                if upload_success:
                    print("  > Drive 업로드 성공. 로컬 파일 정리 중...")
                    try:
                        os.remove(zip_file_path)
                        rmtree(event_output_dir)
                        print("  > 로컬 출력 파일 및 폴더 삭제 완료.")
                    except Exception as e:
                        print(f"[!] 로컬 파일 정리 실패: {e}", file=sys.stderr)
                else:
                    print("  > Drive 업로드 실패. 로컬 폴더를 보존합니다.")
            else:
                print("  > 압축 실패. Drive 업로드를 건너뜁니다.")
        else:
            print("  > Drive 업로드 비활성화. 로컬 폴더를 보존합니다.")


    # 이벤트 리스너 시작
    b_instance["events"].open_perf_buffer(handle_event)

    # 폴링 루프
    try:
        while True:
            b_instance.perf_buffer_poll()
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n🛑 사용자 중단: 감시 프로세스 종료 요청.")
    except Exception as e:
        print(f"치명적 오류 발생: {e}")
    finally:
        print("🛑 종료: 감시 프로세스 종료됨.")


# --- 메인 실행 ---
if __name__ == "__main__":
    if b is None:
        if BPF:
             print("eBPF 'b' 객체가 None입니다. 초기화 실패로 프로그램을 종료합니다.")
        sys.exit(1)
        
    uploader = None
    if GOOGLE_DRIVE_AVAILABLE:
        # DriveUploader 초기화 시 인증 과정이 포함됨
        uploader = DriveUploader()
    else:
        # 모듈이 없으면 더미 Uploader 객체로 대체하여 main_loop 실행 가능하도록 함
        class DummyUploader:
             service = None
        uploader = DummyUploader()


    daemon_context = DaemonizeContext()
    
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'foreground':
        print("💡 포그라운드 모드 실행 중 (Ctrl+C로 종료)")
        with daemon_context:
            # b 객체와 uploader 객체를 main_loop로 전달
            main_loop(b, uploader)
    else:
        print("💡 백그라운드 데몬으로 전환 중... 로그: /tmp/runtime_sbom_monitor.log")
        # b 객체와 uploader 객체를 daemonize로 전달
        daemonize(daemon_context, b, uploader)
