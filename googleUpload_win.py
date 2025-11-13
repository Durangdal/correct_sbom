#!/usr/bin/env python3
import os
import sys
import json
import time
import psutil
import subprocess
from datetime import datetime
from shutil import which, rmtree
import itertools
import hashlib

# ⚠️ Google Drive API Imports (Requires: pip install google-api-python-client google-auth-oauthlib google-auth-httplib2)
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    GOOGLE_DRIVE_READY = True
except ImportError:
    GOOGLE_DRIVE_READY = False
    print("Warning: Google Drive libraries not installed. Automatic upload function will be skipped.")

# Windows 환경에서 파일 버전 정보를 가져오기 위해 pefile 라이브러리 임포트
try:
    import pefile
except ImportError:
    pefile = None
    # Warning message is handled in the original code, no need to repeat

# --- 설정 ---
BASE_DIR = os.getcwd()
SBOM_DIR = os.path.join(BASE_DIR, "sbom_logs")
os.makedirs(SBOM_DIR, exist_ok=True)

LOG_FILE = os.path.join(SBOM_DIR, "sbom_monitor.log")

# Google Drive 설정
SCOPES = ['https://www.googleapis.com/auth/drive.file']
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'
DRIVE_ROOT_FOLDER_NAME = 'SBOM_Monitor_Logs' # Google Drive에 생성될 최상위 폴더 이름

# 감시 대상 실행 파일 (원래 설정 유지)
TARGET_EXECUTABLES = {
    "python", "python.exe",
    "node", "node.exe",
    "java", "java.exe",
    "nginx", "nginx.exe"
}

seen_pids = set()
folder_counter = itertools.count(1)

# --- 유틸리티 ---
def log(msg):
    """콘솔 및 로그 파일에 메시지 기록"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def save_sbom(sbom, filename):
    """SBOM 딕셔너리를 지정된 파일에 저장"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2, ensure_ascii=False)
        log(f"SBOM 저장됨 → {filename} (components={len(sbom['components'])})")
    except Exception as e:
        log(f"SBOM 저장 실패: {e}")

# 파일 해시 계산 (SHA-256) (원래 함수 유지)
def calculate_file_hash(file_path, algorithm='sha256'):
    """파일의 해시값을 계산"""
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b''):
                hasher.update(chunk)
        return f"{algorithm}:{hasher.hexdigest()}"
    except Exception:
        return ""

# Windows 전용: PE 파일(EXE/DLL)에서 버전 정보 추출 (원래 함수 유지)
def get_file_version_info(file_path):
    """Windows PE 파일에서 버전 문자열을 추출"""
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
        # Note: 'pe' is checked for existence implicitly in the original code,
        # but this is safer if it was declared outside try.
        # Since it is declared inside try, the original check is fine but verbose.
        pass # pefile closure handling simplified for robust execution

# 런타임 OS 수준 라이브러리 정보 (버전 정보 및 해시 포함) (원래 함수 유지)
def get_loaded_libs(pid):
    """프로세스에서 로드된 공유 라이브러리 경로 목록, 버전 및 해시 반환"""
    libs_info = {}
    try:
        proc = psutil.Process(pid)
        for m in proc.memory_maps():
            path = getattr(m, "path", None)
            if not path or not os.path.isfile(path) or path.startswith('['):
                continue
            
            if path not in libs_info:
                file_hash = calculate_file_hash(path)
                
                # 1. 버전 정보 추출 시도 (Windows/pefile)
                version = get_file_version_info(path) 
                
                libs_info[path] = {
                    "version": version if version else "runtime", 
                    "hash": file_hash
                }
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        pass
    except Exception as e:
        log(f"라이브러리 로딩 중 예외 발생: {e}")
    return libs_info

# 애플리케이션 내부 의존성 수집 (Syft 프로세스 스캔) (원래 함수 유지)
def get_app_internal_libs(exe_name, pid, output_dir, proc_cmdline):
    # ... (function body remains the same)
    script_path = None
    
    for arg in proc_cmdline:
        if arg.lower().endswith(('.py', '.js', '.jar', '.war')):
            # 파일이 존재하는지 확인
            if os.path.exists(arg):
                script_path = arg
                break
            
    if not script_path:
        log("내부 스캔: Syft 분석을 위한 스크립트/앱 경로를 명령줄에서 찾을 수 없습니다.")
        return None

    if not which("syft"):
        log("Syft 미설치. 내부 의존성 스캔 생략.")
        return None
        
    base_name = exe_name.split('.')[0]
    out_file_name = f"internal_sbom_app_libs_{base_name}_{pid}.json"
    out_file = os.path.join(output_dir, out_file_name)
    
    try:
        # Syft 명령: packages:pid:<PID>를 사용하여 실행 중인 프로세스 내부 스캔
        command = ["syft", script_path, "-o", "cyclonedx-json"]
        log(f"Syft 내부 스캔 시도: 경로 분석 ({script_path})")
        
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            encoding="utf-8", 
            timeout=180, 
            check=True
        )
        
        # Syft가 컴포넌트를 찾지 못했으나, 실행 자체는 성공한 경우
        if "No packages were found" in result.stderr or not result.stdout.strip():
             log(f"Syft 내부 스캔: {exe_name}에서 애플리케이션 패키지 미발견 (SBOM 파일 미생성).")
             return None
             
        with open(out_file, "w", encoding="utf-8") as fout:
            fout.write(result.stdout)
            
        log(f"Syft 내부 SBOM 생성됨 → {out_file} (애플리케이션 계층 의존성)")
        return out_file
        
    except subprocess.CalledProcessError as e:
        log(f"Syft 내부 스캔 실패 (CalledProcessError): {exe_name}. Stderr: {e.stderr.strip()[:100]}...")
    except subprocess.TimeoutExpired:
        log(f"Syft 내부 스캔 시간 초과: {exe_name}")
    except Exception as e:
        log(f"Syft 내부 스캔 실패: {exe_name} ({e})")
    return None

# 환경 변수 및 명령줄 수집 (원래 함수 유지)
def get_process_context(proc):
    # ... (function body remains the same)
    context = {}
    
    # 명령줄 (Command Line) 수집
    try:
        context["command_line"] = " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        context["command_line"] = "N/A"
        
    # 환경 변수 (Environment Variables) 수집 - 중요 변수만 필터링
    env_vars_to_collect = ["PATH", "JAVA_HOME", "PYTHONPATH", "NODE_PATH", "CLASSPATH", "LD_LIBRARY_PATH", "USER", "HOME"]
    env_data = {}
    try:
        process_env = proc.environ() 
        for key in env_vars_to_collect:
            if key in process_env:
                env_data[key] = process_env[key]
        context["environment_variables"] = env_data
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        context["environment_variables"] = {"Note": "Access Denied to environment variables."}
        
    return context

def save_context(context_data, output_dir, pid):
    """수집된 환경 컨텍스트를 별도 JSON 파일로 저장"""
    context_file = os.path.join(output_dir, f"runtime_context_{pid}.json")
    try:
        with open(context_file, "w", encoding="utf-8") as f:
            json.dump(context_data, f, indent=2, ensure_ascii=False)
        log(f"런타임 컨텍스트 저장됨 → {context_file}")
    except Exception as e:
        log(f"컨텍스트 저장 실패: {e}")

def run_syft(exe_file, pid, output_dir):
    """Syft를 사용하여 정적 SBOM을 생성하고 지정된 폴더에 저장"""
    # ... (function body remains the same)
    if not which("syft"):
        log(f"syft 미설치: {exe_file} static SBOM 생략")
        return None
        
    out_file_name = f"static_sbom_{os.path.basename(exe_file)}_{pid}.json"
    out_file = os.path.join(output_dir, out_file_name)
    
    try:
        # Syft 실행: 대상 실행 파일, 출력 형식(cyclonedx-json) 지정
        result = subprocess.run(
            ["syft", exe_file, "-o", "cyclonedx-json"], 
            capture_output=True, 
            text=True, 
            encoding="utf-8", 
            timeout=120,
            check=True
        )
        
        with open(out_file, "w", encoding="utf-8") as fout:
            fout.write(result.stdout)
            
        log(f"Syft Static SBOM 생성됨 → {out_file}")
        return out_file
        
    except subprocess.CalledProcessError as e:
        log(f"syft 실행 실패 (CalledProcessError): {exe_file}. Stderr: {e.stderr.strip()[:100]}...")
    except subprocess.TimeoutExpired:
        log(f"syft 실행 시간 초과: {exe_file}")
    except Exception as e:
        log(f"syft 실행 실패: {exe_file} ({e})")
    return None

def create_cyclonedx_sbom(exe_name, pid, libs_info, runtime=True):
    """CycloneDX 형식의 SBOM 딕셔너리 생성 (해시 및 버전 반영)"""
    # ... (function body remains the same)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": exe_name, "version": "runtime" if runtime else "static"}
        },
        "components": []
    }
    for lib_path, info in libs_info.items(): # libs_info는 딕셔너리({version: ..., hash: ...})를 포함
        lib_name = os.path.basename(lib_path)
        cleaned_path = lib_path.replace(":", "").replace("\\", "/")
        purl = f"pkg:generic/{lib_name}?file_path={cleaned_path}"
        
        comp = {
            "type": "library",
            "name": lib_name,
            "version": info.get("version", "runtime"),
            "purl": purl,
        }
        
        file_hash = info.get("hash")
        if file_hash and file_hash.startswith("sha256:"):
             comp["hashes"] = [{"alg": "SHA-256", "content": file_hash.split(':')[1]}]
             
        sbom["components"].append(comp)
    return sbom

# --- Google Drive 기능 추가 ---

def authenticate_google_drive():
    """Google Drive API 서비스 객체를 인증하고 반환"""
    creds = None
    # 1. token.json 파일에서 저장된 인증 정보 로드
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        log("Google Drive: 저장된 토큰 파일에서 인증 정보 로드 성공.")

    # 2. 유효한 인증 정보가 없거나 만료된 경우 재인증
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # 토큰 새로 고침 시도
            try:
                creds.refresh(Request())
                log("Google Drive: 토큰 새로 고침 성공.")
            except Exception as e:
                log(f"Google Drive: 토큰 새로 고침 실패. 재인증 필요: {e}")
                creds = None
        
        if not creds and os.path.exists(CREDENTIALS_FILE):
            # 대화형 인증 흐름 실행
            log("Google Drive: 대화형 인증 시작 (브라우저에서 승인 필요).")
            try:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
                # 새로 획득한 토큰 저장
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
                log("Google Drive: 인증 완료 및 토큰 저장.")
            except Exception as e:
                log(f"Google Drive: 인증 실패. '{CREDENTIALS_FILE}' 파일을 확인하세요. 오류: {e}")
                return None
        elif not os.path.exists(CREDENTIALS_FILE):
            log(f"Google Drive: '{CREDENTIALS_FILE}' 파일이 없습니다. 인증을 건너뜝니다.")
            return None
    
    if creds:
        try:
            # Drive API 서비스 객체 생성
            service = build('drive', 'v3', credentials=creds)
            return service
        except Exception as e:
            log(f"Google Drive: 서비스 객체 빌드 실패: {e}")
            return None
    
    return None

def find_or_create_folder(service, folder_name, parent_id=None):
    """Google Drive에서 폴더를 찾아 ID를 반환하거나 새로 생성"""
    if not service:
        return None

    # 폴더 검색 쿼리
    query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    if parent_id:
        query += f" and '{parent_id}' in parents"
    
    response = service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
    files = response.get('files', [])

    if files:
        # 폴더가 이미 존재하는 경우
        return files[0]['id']
    else:
        # 폴더가 없는 경우 새로 생성
        file_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder'
        }
        if parent_id:
            file_metadata['parents'] = [parent_id]
        
        folder = service.files().create(body=file_metadata, fields='id').execute()
        return folder.get('id')

def upload_folder_contents(service, local_folder_path, drive_folder_id):
    """로컬 폴더의 모든 파일을 Google Drive 폴더로 업로드"""
    if not service or not drive_folder_id:
        return

    for filename in os.listdir(local_folder_path):
        local_filepath = os.path.join(local_folder_path, filename)

        if os.path.isfile(local_filepath):
            # 파일 메타데이터 설정
            file_metadata = {
                'name': filename,
                'parents': [drive_folder_id]
            }
            # MIME 타입 추정 (예시: JSON 파일)
            mime_type = 'application/json' if filename.endswith('.json') else 'text/plain'
            
            # MediaFileUpload 객체 생성
            media = MediaFileUpload(local_filepath, mimetype=mime_type, resumable=True)
            
            try:
                # 파일 업로드 실행
                service.files().create(body=file_metadata, media_body=media, fields='id, name').execute()
                log(f"Google Drive: 파일 업로드 성공 → {filename}")
            except Exception as e:
                log(f"Google Drive: '{filename}' 업로드 실패: {e}")


# --- 메인 루프 ---
def main():
    log("🏁 개별 프로세스 SBOM 감시 시작 (Google Drive 자동 업로드 기능 활성화)")
    
    google_drive_service = None
    if GOOGLE_DRIVE_READY:
        google_drive_service = authenticate_google_drive()
        if google_drive_service:
            # Google Drive 루트 폴더 ID를 미리 획득
            root_folder_id = find_or_create_folder(google_drive_service, DRIVE_ROOT_FOLDER_NAME)
            log(f"Google Drive: 로그 저장 폴더 ID 획득: {root_folder_id}")
        else:
            log("Google Drive 서비스 초기화 실패. 업로드를 건너뜜.")
            root_folder_id = None
    else:
        root_folder_id = None # 라이브러리 미설치 시 업로드 건너뛰기

    
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
                
                # 1. 프로세스 컨텍스트 수집 및 로깅
                context_data = get_process_context(proc)
                command = context_data.get("command_line", "N/A")
                log(f"✅ 실행 감지: {exe_name_raw} (PID={pid}) → CMD: {command}")

                # 2. 프로세스별 저장 폴더 생성 (로컬)
                timestamp_str = datetime.now().strftime("%Y%m%dT%H%M%S")
                counter = next(folder_counter)
                base_name = exe_name.split('.')[0] 
                new_folder_name = f"{base_name}_{timestamp_str}_{counter}"
                output_dir = os.path.join(SBOM_DIR, new_folder_name)
                os.makedirs(output_dir, exist_ok=True)
                log(f"새 SBOM 폴더 생성 (로컬): {output_dir}")
                
                # 3. 런타임 환경 컨텍스트 저장 (환경 변수 및 명령줄)
                save_context(context_data, output_dir, pid)

                # 4. OS 수준 런타임 SBOM 생성
                libs_info = get_loaded_libs(pid)
                runtime_sbom_os = create_cyclonedx_sbom(exe_name_raw, pid, libs_info, runtime=True)
                runtime_output_file = os.path.join(output_dir, f"runtime_sbom_os_libs_{pid}.json")
                save_sbom(runtime_sbom_os, runtime_output_file) # <-- save_sbom 호출

                # 5. 애플리케이션 내부 의존성 SBOM 생성 (Syft 프로세스 스캔)
                get_app_internal_libs(exe_name, pid, output_dir, proc_cmdline_list)
                
                # 6. Static SBOM 생성 (Syft)
                if exe_file:
                    run_syft(exe_file, pid, output_dir)
                    
                # 7. --- Google Drive 자동 업로드 (새로운 기능) ---
                if google_drive_service and root_folder_id:
                    log(f"Google Drive 업로드 시작: {new_folder_name}")
                    
                    # Google Drive에 서브 폴더 생성
                    drive_sub_folder_id = find_or_create_folder(
                        google_drive_service, 
                        new_folder_name, 
                        root_folder_id
                    )
                    
                    if drive_sub_folder_id:
                        # 로컬 폴더의 내용을 Drive 서브 폴더로 업로드
                        upload_folder_contents(google_drive_service, output_dir, drive_sub_folder_id)
                        
                        # 업로드 후 로컬 로그 폴더 삭제 (선택 사항: 디스크 공간 절약)
                        try:
                             rmtree(output_dir)
                             log(f"로컬 폴더 삭제 완료: {output_dir}")
                        except Exception as e:
                             log(f"로컬 폴더 삭제 실패: {e}")
                    else:
                        log(f"Google Drive에 서브 폴더 생성 실패. 업로드 건너뜀.")
                else:
                    log("Google Drive 서비스가 준비되지 않아 업로드를 건너뜝니다.")


            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log(f"예외 발생: {e}")
        
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("프로그램 종료 요청 (Ctrl+C).")
        sys.exit(0)
    except Exception as e:
        log(f"치명적인 오류 발생: {e}")
        sys.exit(1)
