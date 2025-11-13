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

# --- 전역 설정 ---
BASE_OUTPUT_DIR = "/tmp/runtime_sbom_outputs"
# 순차적 번호 관리를 위한 카운터와 락
global_counter = count(1)
counter_lock = threading.Lock()


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

# --- 🔽 [***수정된 부분 1: daemonize가 b 객체를 받도록 수정***] 🔽 ---
# (전역 변수 'b'를 main_loop로 안정적으로 전달하기 위함)
def daemonize(context_manager, b_obj): 
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
        # b 객체 전달
        main_loop(b_obj)
# --- 🔼 [***수정 완료 1***] 🔼 ---


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

# --- 상세 정보 수집 헬퍼 (Script 2의 고급 기능) ---
# --- (모든 기능 유지) ---
def get_pkg_info(path):
    """Debian/Ubuntu 환경에서 파일 경로로부터 dpkg 패키지 정보를 조회합니다."""
    if not which("dpkg"):
        return None, None, None # dpkg가 없으면 스킵
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
    """
    단일 PID에 대해 상세 정보를 수집합니다.
    (memory_peak 및 network_calls 수집 로직 강화)
    """
    try:
        p = psutil.Process(pid)
        name = p.name()
        path = p.exe()
        threads = p.num_threads()
        status = p.status()

        # 1. PID (매개변수)
        # 2. Description (name, path)
        
        # 3. Memory (현재 + 최대)
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
        
        # 4. Network (누적 IO)
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
                    "version": "1.9-all-features-fixed" # 버전 업데이트
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
        print(f"  > get_loaded_libs(pid={pid}) 스캔 실패: 프로세스가 이미 종료됨.")
    except Exception as e:
        print(f"  > get_loaded_libs(pid={pid}) 오류: {e}")
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
        print(f"  > Syft 정적 SBOM 생성됨: {out_file_name}")
        
    except subprocess.CalledProcessError as e:
        # Syft < v1.0 (syft packages file:...)
        if "unknown command \"scan\"" in e.stderr:
            print("  > 'syft scan' 실패. 구버전 'syft packages'로 재시도...")
            try:
                result = subprocess.run(
                    ["syft", "packages", f"file:{exe_file}", "-o", "cyclonedx-json"],
                    capture_output=True, check=True, timeout=60, encoding="utf-8"
                )
                with open(out_file, "w", encoding="utf-8") as fout:
                    fout.write(result.stdout)
                print(f"  > Syft (구버전) 정적 SBOM 생성됨: {out_file_name}")
            except Exception as e2:
                print(f"[!] syft (구버전) 실행도 실패: {e2}")
        else:
            print(f"[!] syft 실행 실패 (종료 코드 {e.returncode}): {e.cmd}")
            syft_stderr = e.stderr.strip() if e.stderr else '표준 오류 출력 없음'
            print(f"    Syft Stderr: {syft_stderr[:500] if len(syft_stderr) > 500 else syft_stderr}")
    except FileNotFoundError:
        print("[!] syft 실행 파일을 찾을 수 없습니다. (PATH 문제)")
    except subprocess.TimeoutExpired:
        print(f"[!] syft 실행 시간 초과 (60초 초과): {exe_file}")
    except Exception as e:
        print(f"[!] syft 실행 중 예상치 못한 오류 발생: {type(e).__name__}: {e}")


# --- eBPF 초기화 (Script 1 방식) ---
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


# --- 🔽 [***수정된 부분 2: main_loop가 b 객체를 인자로 받음***] 🔽 ---
def main_loop(b_instance):
    # --- 🔽 [***수정된 부분 3: 'if not b'를 'if b is None'으로 수정***] 🔽 ---
    if b_instance is None:
        print("eBPF가 초기화되지 않아 (b_instance is None) 메인 루프를 시작할 수 없습니다.")
        return
    # --- 🔼 [***수정 완료 3***] 🔼 ---

    os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)
    print(f"🚀 런타임 SBOM 감시 시작 (PID: {os.getpid()})")
    print(f"📄 모든 SBOM 출력은 하위 디렉토리에 저장됩니다: {BASE_OUTPUT_DIR}")

    # eBPF 이벤트 핸들러
    def handle_event(cpu, data, size):
        global global_counter
        
        # 1. 이벤트 데이터 파싱
        try:
            # C 코드의 익명 struct { ... } data;를 참조합니다
            event = b_instance["events"].event(data)
            
            proc_name_raw = event.comm.decode("utf-8", "replace")
            exe_file = event.filename.decode("utf-8", "replace")
            pid = event.pid
        except Exception as e:
            print(f"[!] 이벤트 파싱 실패: {e}")
            return
            
        if proc_name_raw == 'syft':
            return
        
        if proc_name_raw.startswith('python') and ('runtime_sbom_monitor' in exe_file or 'Linux_SBOM_test' in exe_file):
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
            print(f"[!] 폴더 생성 충돌 감지 (무시): {event_output_dir_name}")
            return
        except Exception as e:
            print(f"[!] 폴더 생성 실패: {e}")
            return

        # 3. 런타임 SBOM 생성
        runtime_sbom = new_sbom()
        seen_purls = set()
        
        time.sleep(0.1) # 프로세스 로드 대기

        # 4. 고급 정보 수집 (Script 2 기능)
        process_info = get_process_info(pid)
        
        # 5. 메인 컴포넌트 추가
        main_component = {
            "type": "application",
            "name": proc_name_raw, # 'description'
            "version": "runtime",
            "properties": [
                {"name": "file_path", "value": exe_file}, # 'description'
                {"name": "pid", "value": str(pid)} # 'pid'
            ]
        }

        if process_info:
            if process_info.get('PURL'):
                main_component['purl'] = process_info['PURL']
                main_component['version'] = process_info.get('Version', 'runtime')
            else:
                main_component['purl'] = f"pkg:generic/{proc_name_raw}?pid={pid}&exe={exe_file}"

            # 4가지 특성 반영 (memory_peak, network_calls 등)
            main_component["properties"].extend([
                {"name": "status", "value": process_info.get('Status', 'unknown')},
                {"name": "threads", "value": str(process_info.get('Threads', '0'))},
                {"name": "memoryPercent", "value": f"{process_info.get('MemoryPercent', 0):.2f}%"},
                {"name": "memoryPeakKB", "value": str(process_info.get('MemoryPeakKB', '0'))} # memory_peak
            ])
            
            net_io_data = process_info.get('NetIOCounters', {}) # network_calls
            for key, value in net_io_data.items():
                main_component["properties"].append({"name": f"netIO_{key}", "value": str(value)})

            if process_info.get('Package'):
                 main_component["properties"].append({"name": "dpkg.package", "value": process_info.get('Package')}) # 'description'

        else:
            main_component['purl'] = f"pkg:generic/{proc_name_raw}?pid={pid}&status=terminated"

        runtime_sbom["components"].append(main_component)
        seen_purls.add(main_component['purl'])

        # 6. Python/Java 라이브러리 추가 (Script 2 기능)
        if process_info and process_info.get('Libraries'):
            for lib in process_info['Libraries']:
                lib_name = lib.get('Name', 'unknown-lib')
                lib_path = lib.get('Path', 'unknown-path')
                proc_name_lower = process_info.get('Name', '').lower()

                if proc_name_lower.startswith('python'):
                    lib_type, purl = "library", f"pkg:pypi/{lib_name}"
                elif proc_name_lower == 'java':
                    lib_type = "library"
                    ver_match = re.search(r'-([\d\.]+.*?)(\.jar)', lib_name)
                    version = ver_match.group(1) if ver_match else "runtime"
                    base_name = lib_name.replace(f"-{version}", "") if ver_match else lib_name.replace(".jar", "")
                    purl = f"pkg:maven/unknown/{base_name}@{version}"
                else:
                    lib_type, purl = "library", f"pkg:generic/{lib_name}?path={lib_path}"

                if purl not in seen_purls:
                    runtime_sbom["components"].append({
                        "type": lib_type, "name": lib_name, "purl": purl,
                        "properties": [{"name": "file_path", "value": lib_path}]
                    })
                    seen_purls.add(purl)

        # 7. 로드된 공유 라이브러리(.so) 추가
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

        # 8. 런타임 SBOM 저장
        runtime_sbom_file_name = f"cyclonedx-runtime-sbom.json"
        runtime_sbom_path = os.path.join(event_output_dir, runtime_sbom_file_name)
        
        try:
            with open(runtime_sbom_path, "w", encoding="utf-8") as f:
                json.dump(runtime_sbom, f, indent=2, ensure_ascii=False)
            print(f"  > 런타임 SBOM 저장 완료 ({len(runtime_sbom['components'])}개 컴포넌트): {runtime_sbom_file_name}")
        except Exception as e:
            print(f"[!] 런타임 SBOM 저장 실패: {e}")

        # 9. Syft 실행
        run_syft(exe_file, pid, event_output_dir)

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
    if not BPF:
        print("bcc(eBPF) 라이브러리를 찾을 수 없거나 초기화에 실패했습니다.")
        print("프로그램을 종료합니다. bcc-tools 또는 python3-bcc 패키지를 설치하세요.")
        sys.exit(1)
        
    # --- 🔽 [***수정된 부분 4: 'if b is None' 검사 추가***] 🔽 ---
    # eBPF 초기화가 위에서 실패했으면 b는 None일 것임
    if b is None: 
        print("eBPF 'b' 객체가 None입니다. 초기화 실패로 프로그램을 종료합니다.")
        sys.exit(1)
    # --- 🔼 [***수정 완료 4***] 🔼 ---

    daemon_context = DaemonizeContext()
    
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'foreground':
        print("💡 포그라운드 모드 실행 중 (Ctrl+C로 종료)")
        with daemon_context:
            # b 객체를 main_loop로 전달
            main_loop(b)
    else:
        print("💡 백그라운드 데몬으로 전환 중... 로그: /tmp/runtime_sbom_monitor.log")
        # b 객체를 daemonize로 전달
        daemonize(daemon_context, b)
