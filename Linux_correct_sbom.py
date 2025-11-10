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
from datetime import datetime, timezone
from shutil import which
from itertools import count

# --- 전역 설정 (Script 1) ---
BASE_OUTPUT_DIR = "/tmp/runtime_sbom_outputs"
# 순차적 번호 관리를 위한 카운터와 락
global_counter = count(1)
counter_lock = threading.Lock()


# --- 데몬화 컨텍스트 관리자 (Script 1) ---
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

def daemonize(context_manager):
    # 1차 fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"1차 fork 실패: {e}\n")
        sys.exit(1)

    # 새 세션 리더가 됨
    os.setsid()

    # 2차 fork (터미널 재연결 방지)
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"2차 fork 실패: {e}\n")
        sys.exit(1)

    # 환경 설정
    os.chdir("/")
    os.umask(0)

    # 파일 디스크립터 정리 및 표준 입출력 리디렉션
    try:
        sys.stdin.close()
    except OSError:
        pass # 이미 닫혀있을 수 있음

    with context_manager as ctx:
        os.dup2(ctx.stdout.fileno(), sys.stdout.fileno())
        os.dup2(ctx.stderr.fileno(), sys.stderr.fileno())
        # 데몬화 완료 후 메인 루프 시작
        main_loop()


# --- eBPF 코드 (Script 1) ---
bpf_program_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// execve 이벤트 데이터를 커널에서 유저스페이스로 전달하기 위한 구조체
struct exec_data_t {
    u32 pid;
    char comm[TASK_COMM_LEN]; // 프로세스 이름
    char filename[256];      // 실행 파일 경로 (128 -> 256으로 확장)
};

BPF_PERF_OUTPUT(events);

// execve 시스템 콜의 진입점(entry)을 트레이싱
int trace_execve_entry(struct pt_regs *ctx, const char __user *filename) {
    struct exec_data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 사용자 공간 메모리에서 파일 경로를 읽어옴
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    // perf 버퍼를 통해 유저스페이스로 데이터 전송
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# --- 상세 정보 수집 헬퍼 (Script 2) ---
def get_pkg_info(path):
    """Debian/Ubuntu 환경에서 파일 경로로부터 dpkg 패키지 정보를 조회합니다."""
    if not which("dpkg"):
        return None, None, None # dpkg가 없으면 스킵
    try:
        # 'dpkg -S'로 파일이 속한 패키지 이름 찾기
        output = subprocess.check_output(['dpkg', '-S', path], stderr=subprocess.STDOUT, text=True)
        match = re.search(r'([\w\d\.\-]+):', output)
        if match:
            pkg_name = match.group(1)
            # 'dpkg -l'로 패키지 버전 찾기
            ver_output = subprocess.check_output(['dpkg', '-l', pkg_name], text=True)
            # dpkg -l 출력의 5번째 줄(헤더 제외)에서 버전 정보 파싱
            lines = ver_output.split('\n')
            if len(lines) > 5:
                ver_match = re.search(r'^\S+\s+' + re.escape(pkg_name) + r'\s+(\S+)\s+(\S+)\s+', lines[5])
                if ver_match:
                    version = ver_match.group(1) # [1]이 버전, [2]가 아키텍처
                    # PURL 생성 (os-release를 읽는 것이 더 정확하지만, 여기서는 ubuntu로 가정)
                    purl = f"pkg:deb/ubuntu/{pkg_name}@{version}"
                    return pkg_name, version, purl
    except Exception:
        # dpkg -S가 실패(파일이 패키지에 속하지 않음)하거나 파싱 실패 시
        pass
    return None, None, None

def get_pip_libs(pid):
    """실행 중인 Python 프로세스에서 로드된 라이브러리(.so)를 추측합니다."""
    libs = []
    try:
        p = psutil.Process(pid)
        for lib in p.memory_maps():
            # /usr/lib/python* 또는 /usr/local/lib/python* 경로의 .so 파일 스캔
            if ('/usr/lib/python' in lib.path or '/usr/local/lib/python' in lib.path) and lib.path.endswith('.so'):
                # 예: .../dist-packages/numpy/core/_multiarray_umath.cpython-310-x86_64-linux-gnu.so
                # -> numpy 시도
                parts = lib.path.split('/')
                try:
                    dist_index = parts.index('dist-packages')
                    if dist_index + 1 < len(parts):
                        lib_name = parts[dist_index + 1].split('.')[0] # 'numpy'
                    else:
                        continue
                except ValueError:
                    # dist-packages가 없는 경우, .so 파일 이름에서 추측 (정확도 낮음)
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
    """단일 PID에 대해 상세 정보를 수집합니다. (Script 2의 핵심 로직)"""
    try:
        p = psutil.Process(pid)
        name = p.name()
        path = p.exe()
        threads = p.num_threads()
        status = p.status()

        # 메모리 및 네트워크 사용량 수집
        memory_percent = p.memory_percent()
        try:
            net_connections = len(p.connections())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            net_connections = 0 # 권한 문제 또는 프로세스 종료 시

        base_info = {
            'PID': pid,
            'Name': name,
            'Path': path,
            'Threads': threads,
            'Status': status,
            'MemoryPercent': memory_percent,
            'NetConnections': net_connections
        }

        # 인터프리터(Python, Java 등) 감지
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
            # 일반 바이너리인 경우, dpkg 정보 조회
            pkg_name, version, purl = get_pkg_info(path)
            if pkg_name:
                base_info['Package'] = pkg_name
                base_info['Version'] = version
                base_info['PURL'] = purl
            return base_info

    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        # 프로세스가 이미 종료되었거나 권한이 없는 경우
        pass
    return None


# --- SBOM 및 Syft 헬퍼 (Script 1) ---
def new_sbom():
    """새로운 CycloneDX 1.5 SBOM 템플릿을 생성합니다."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            # datetime.utcnow() 대신 timezone.utc 사용
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "custom",
                    "name": "runtime-sbom-monitor",
                    "version": "1.1-merged"
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
            # 유효한 파일 경로인지 확인
            if not path or not os.path.isabs(path) or not os.path.isfile(path):
                continue
            # [vsyscall] 등 가상 경로 제외
            if path.startswith("["):
                continue
            # .so 파일 또는 /lib/ 경로에 있는 파일들 (주로 .so)
            if '.so' in path or path.startswith('/lib/'):
                 if path not in libs_info:
                    libs_info[path] = "runtime"
    except psutil.NoSuchProcess:
        # 프로세스가 너무 빨리 종료되면 스캔 실패
        print(f"  > get_loaded_libs(pid={pid}) 스캔 실패: 프로세스가 이미 종료됨.")
    except Exception as e:
        print(f"  > get_loaded_libs(pid={pid}) 오류: {e}")
    return libs_info

def run_syft(exe_file: str, pid: int, output_dir: str):
    """Syft를 실행하여 정적 SBOM을 생성합니다."""
    if not which("syft"):
        print("[!] syft 미설치: 정적 SBOM 생략")
        return

    # 실행 파일 경로 유효성 검사
    if not exe_file or not os.path.isabs(exe_file) or not os.path.exists(exe_file):
        print(f"[!] syft 스킵: 유효한 실행 파일 경로가 아닙니다. 경로: '{exe_file}'")
        return
    
    out_file_name = f"cyclonedx-static-sbom.json"
    out_file = os.path.join(output_dir, out_file_name)
    
    try:
        # syft 실행
        result = subprocess.run(
            ["syft", "scan", f"file:{exe_file}", "-o", "cyclonedx-json"],
            capture_output=True,
            check=True,
            timeout=60,
            encoding="utf-8"
        )
        
        with open(out_file, "w", encoding="utf-8") as fout:
            fout.write(result.stdout)

        print(f"  > Syft 정적 SBOM 생성됨: {out_file_name}")
        
    except subprocess.CalledProcessError as e:
        print(f"[!] syft 실행 실패 (종료 코드 {e.returncode}): {e.cmd}")
        syft_stderr = e.stderr.strip() if e.stderr else '표준 오류 출력 없음'
        print(f"    Syft Stderr: {syft_stderr[:500] if len(syft_stderr) > 500 else syft_stderr}")
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
        # kprobe를 사용하여 execve 시스템 콜의 진입점에 함수 연결
        syscall_fnname = b.get_syscall_fnname("execve")
        b.attach_kprobe(event=syscall_fnname, fn_name="trace_execve_entry")
    except Exception as e:
        print(f"치명적 오류: eBPF 초기화 실패: {e}")
        print("루트 권한(sudo)으로 실행했는지 확인하세요.")
        BPF = None # BPF 사용 불가로 플래그 변경
else:
    print("eBPF (bcc) 모듈이 없어 실행 감지를 시작할 수 없습니다.")


# --- 메인 루프 (Script 1) 및 이벤트 핸들러 (병합) ---
def main_loop():
    if not b:
        print("eBPF가 초기화되지 않아 메인 루프를 시작할 수 없습니다.")
        return

    os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)
    print(f"🚀 런타임 SBOM 감시 시작 (PID: {os.getpid()})")
    print(f"📄 모든 SBOM 출력은 하위 디렉토리에 저장됩니다: {BASE_OUTPUT_DIR}")

    # eBPF 이벤트 핸들러 (Script 1 + Script 2 로직 병합)
    def handle_event(cpu, data, size):
        global global_counter
        
        # 1. 이벤트 데이터 파싱
        try:
            event = b["events"].event(data)
            proc_name_raw = event.comm.decode("utf-8", "replace")
            exe_file = event.filename.decode("utf-8", "replace")
            pid = event.pid
        except Exception as e:
            print(f"[!] 이벤트 파싱 실패: {e}")
            return
            
        # (참고) 자기 자신(모니터) 또는 syft가 실행되는 것은 무시
        if proc_name_raw.startswith('python') and 'runtime_sbom' in exe_file:
            return
        if proc_name_raw == 'syft':
            return

        # 2. 출력 디렉토리 생성
        proc_name = proc_name_raw.replace('/', '_').replace(' ', '_').replace('.', '_')
        current_time = datetime.now()
        timestamp_str = current_time.strftime("%Y%m%d%H%M%S")

        with counter_lock:
            sequence_num = next(global_counter)
        
        event_output_dir_name = f"{proc_name}_{timestamp_str}_{sequence_num:04d}"
        event_output_dir = os.path.join(BASE_OUTPUT_DIR, event_output_dir_name)
        
        try:
            os.makedirs(event_output_dir, exist_ok=False)
            print(f"[{current_time.strftime('%H:%M:%S')}] [실행 감지] {proc_name_raw} (PID={pid}). 출력 폴더 생성: {event_output_dir_name}")
        except FileExistsError:
            # 거의 동시에 같은 이름의 프로세스가 실행된 경우 (매우 드묾)
            print(f"[!] 폴더 생성 충돌 감지 (무시): {event_output_dir_name}")
            return
        except Exception as e:
            print(f"[!] 폴더 생성 실패: {e}")
            return

        # 3. 런타임 SBOM 생성
        runtime_sbom = new_sbom()
        seen_purls = set() # 중복 컴포넌트 방지
        
        # execve가 반환되고 프로세스가 메모리에 로드될 시간을 약간 대기 (중요)
        time.sleep(0.1) 

        # 4. Script 2 로직: 상세 정보 수집 (get_process_info)
        process_info = get_process_info(pid)
        
        # 5. 메인 컴포넌트 추가 (실행된 바이너리)
        main_component = {
            "type": "application",
            "name": proc_name_raw,
            "version": "runtime",
            "properties": [{"name": "file_path", "value": exe_file}]
        }

        if process_info:
            # Script 2의 정보로 메인 컴포넌트 강화
            if process_info.get('PURL'):
                main_component['purl'] = process_info['PURL']
                main_component['version'] = process_info.get('Version', 'runtime') # dpkg 버전 사용
            else:
                main_component['purl'] = f"pkg:generic/{proc_name_raw}?pid={pid}&exe={exe_file}"

            # Script 2의 리소스 정보 추가
            main_component["properties"].extend([
                {"name": "status", "value": process_info.get('Status', 'unknown')},
                {"name": "threads", "value": str(process_info.get('Threads', '0'))},
                {"name": "memoryPercent", "value": f"{process_info.get('MemoryPercent', 0):.2f}%"},
                {"name": "netConnections", "value": str(process_info.get('NetConnections', '0'))}
            ])
            if process_info.get('Package'):
                 main_component["properties"].append({"name": "dpkg.package", "value": process_info.get('Package')})

        else:
            # 프로세스가 너무 빨리 종료되어 get_process_info가 실패한 경우
            main_component['purl'] = f"pkg:generic/{proc_name_raw}?pid={pid}&exe={exe_file}&status=terminated"

        runtime_sbom["components"].append(main_component)
        seen_purls.add(main_component['purl'])

        # 6. Script 2 로직: Python/Java 라이브러리 추가
        if process_info and process_info.get('Libraries'):
            for lib in process_info['Libraries']:
                lib_name = lib.get('Name', 'unknown-lib')
                lib_path = lib.get('Path', 'unknown-path')
                
                if name.lower().startswith('python'):
                    lib_type = "library"
                    purl = f"pkg:pypi/{lib_name}" # PURL 추측
                elif name.lower() == 'java':
                    lib_type = "library"
                    # JAR 파일 이름에서 버전 추측 시도 (예: log4j-core-2.17.1.jar)
                    ver_match = re.search(r'-([\d\.]+.*?)(\.jar)', lib_name)
                    version = ver_match.group(1) if ver_match else "runtime"
                    base_name = lib_name.replace(f"-{version}", "") if ver_match else lib_name.replace(".jar", "")
                    purl = f"pkg:maven/unknown/{base_name}@{version}" # PURL 추측
                else:
                    lib_type = "library"
                    purl = f"pkg:generic/{lib_name}?path={lib_path}"

                if purl not in seen_purls:
                    runtime_sbom["components"].append({
                        "type": lib_type,
                        "name": lib_name,
                        "purl": purl,
                        "properties": [{"name": "file_path", "value": lib_path}]
                    })
                    seen_purls.add(purl)

        # 7. Script 1 로직: 로드된 공유 라이브러리(.so) 추가
        libs_info = get_loaded_libs(pid)
        for lib_path, version in libs_info.items():
            lib_name = os.path.basename(lib_path)
            purl = f"pkg:generic/{lib_name}?path={lib_path}" # .so 파일은 generic PURL 사용
            
            if purl not in seen_purls:
                runtime_sbom["components"].append({
                    "type": "library",
                    "name": lib_name,
                    "version": version,
                    "purl": purl,
                    "properties": [{"name": "file_path", "value": lib_path}]
                })
                seen_purls.add(purl)

        # 8. 런타임 SBOM 저장
        runtime_sbom_file_name = f"cyclonedx-runtime-sbom.json"
        runtime_sbom_path = os.path.join(event_output_dir, runtime_sbom_file_name)
        
        try:
            with open(runtime_sbom_path, "w", encoding="utf-8") as f:
                json.dump(runtime_sbom, f, indent=2, ensure_ascii=False)
            print(f"  > 런타임 SBOM 저장 완료 ({len(runtime_sbom['components'])}개 컴포넌트): {runtime_sbom_file_name}")
        except Exception as e:
            print(f"[!] 런타임 SBOM 저장 실패: {e}")

        # 9. Syft 실행 (정적 분석)
        run_syft(exe_file, pid, event_output_dir)

    # 이벤트 리스너 시작
    b["events"].open_perf_buffer(handle_event)

    # Ctrl+C를 안정적으로 처리하기 위한 폴링 루프
    try:
        while True:
            # poll 호출: 이벤트를 처리
            b.perf_buffer_poll()
            # 0.1초 대기: CPU 부하를 줄이고 KeyboardInterrupt 시그널을 받을 시간을 확보
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n🛑 사용자 중단: 감시 프로세스 종료 요청.")
    except Exception as e:
        print(f"치명적 오류 발생: {e}")
    finally:
        print("🛑 종료: 감시 프로세스 종료됨.")


# --- 메인 실행 (Script 1) ---
if __name__ == "__main__":
    # bcc(BPF)가 로드되지 않았으면 데몬을 실행할 수 없음
    if not BPF:
        print("bcc(eBPF) 라이브러리를 찾을 수 없거나 초기화에 실패했습니다.")
        print("프로그램을 종료합니다. bcc-tools 또는 python3-bcc 패키지를 설치하세요.")
        sys.exit(1)
        
    daemon_context = DaemonizeContext()
    
    # 'foreground' 인수가 주어지면 데몬화하지 않고 실행
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'foreground':
        print("💡 포그라운드 모드 실행 중 (Ctrl+C로 종료)")
        # 컨텍스트 관리자(PID 파일)는 포그라운드 모드에서도 사용
        with daemon_context:
            main_loop()
    else:
        # 데몬으로 실행
        print("💡 백그라운드 데몬으로 전환 중... 로그: /tmp/runtime_sbom_monitor.log")
        daemonize(daemon_context)
