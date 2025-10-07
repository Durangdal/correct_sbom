#!/usr/bin/python3
from bcc import BPF
import ctypes as ct
import json, os, subprocess, psutil
from datetime import datetime, timezone # timezone 추가
from shutil import which
import platform
import sys
import threading
from itertools import count # 순차적 번호를 위한 모듈
import time # sleep 기능을 위해 time 모듈 추가

# 전역 설정
BASE_OUTPUT_DIR = "/tmp/runtime_sbom_outputs"
# 순차적 번호 관리를 위한 카운터와 락
global_counter = count(1)
counter_lock = threading.Lock()

# 필요한 경우 파일 디스크립터 정리 및 표준 입출력 리디렉션을 위한 컨텍스트 관리자
class DaemonizeContext:
    def __init__(self, pid_file='/tmp/runtime_sbom_monitor.pid', stdout_file='/tmp/runtime_sbom_monitor.log', stderr_file='/tmp/runtime_sbom_monitor.log'):
        self.pid_file = pid_file
        self.stdout = open(stdout_file, 'a+', encoding='utf-8') 
        self.stderr = open(stderr_file, 'a+', buffering=1, encoding='utf-8') 

    def __enter__(self):
        self.cleanup_pid()
        self.write_pid()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 종료 시 PID 파일 제거
        if os.path.exists(self.pid_file):
            os.remove(self.pid_file)
        self.stdout.close()
        self.stderr.close()

    def cleanup_pid(self):
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                if psutil.pid_exists(pid):
                    print(f"경고: PID {pid}를 가진 모니터가 이미 실행 중입니다. 기존 프로세스를 종료하세요.")
                    sys.exit(1)
                os.remove(self.pid_file)
            except:
                pass

    def write_pid(self):
        with open(self.pid_file, 'w') as f:
            f.write(str(os.getpid()))

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
    sys.stdin.close()
    
    with context_manager as ctx:
        os.dup2(ctx.stdout.fileno(), sys.stdout.fileno())
        os.dup2(ctx.stderr.fileno(), sys.stderr.fileno())
        main_loop()


# eBPF 코드 (execve 감시)
bpf_program_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct {
        u32 pid;
        char comm[TASK_COMM_LEN];
        char filename[128];
    } data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# eBPF 설정
b = BPF(text=bpf_program_code)
syscall_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall_fnname, fn_name="trace_execve")

# new_sbom 함수: datetime.utcnow() 경고 수정
def new_sbom():
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
                    "name": "runtime-monitor",
                    "version": "1.0"
                }
            ],
            "component": {
                "type": "application",
                "name": "runtime-monitor",
                "version": "1.0"
            },
            "properties": [
                {"name": "host.os", "value": platform.system()},
                {"name": "host.os_version", "value": platform.version()},
                {"name": "host.kernel", "value": platform.release()},
                {"name": "host.arch", "value": platform.machine()}
            ]
        },
        "components": []
    }

# get_loaded_libs 함수
def get_loaded_libs(pid: int) -> dict:
    libs_info = {}
    try:
        proc = psutil.Process(pid)
        for m in proc.memory_maps():
            path = getattr(m, "path", None)
            if not path or not os.path.isabs(path) or not os.path.isfile(path):
                continue
            if path.startswith("["):
                 continue
            if path in libs_info:
                continue
            libs_info[path] = "runtime" 
    except psutil.NoSuchProcess:
         pass 
    except Exception:
        pass
    return libs_info

# run_syft 함수: 실행 파일 경로 유효성 검사 추가 및 오류 상세 로그 개선
def run_syft(exe_file: str, pid: int, output_dir: str):
    if not which("syft"):
        print("[!] syft 미설치: 정적 SBOM 생략")
        return
    
    # *** 중요: 실행 파일 경로 유효성 검사 ***
    if not exe_file or not os.path.isabs(exe_file) or not os.path.exists(exe_file):
        print(f"[!] syft 스킵: 유효한 실행 파일 경로가 아닙니다. 경로: '{exe_file}'")
        return
    
    out_file_name = f"cyclonedx-static-sbom.json"
    out_file = os.path.join(output_dir, out_file_name)
    
    try:
        result = subprocess.run(
            ["syft", exe_file, "-o", "cyclonedx-json"],
            capture_output=True, 
            check=True,
            timeout=60,
            encoding="utf-8"
        )
        
        with open(out_file, "w", encoding="utf-8") as fout:
            fout.write(result.stdout)

        print(f"[+] Syft 정적 SBOM 생성됨 → {out_file}")
        
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


# 메인 루프를 함수로 분리
def main_loop():
    os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)
    print(f"🚀 런타임 SBOM 감시 시작 (PID: {os.getpid()})")
    print(f"📄 모든 SBOM 출력은 하위 디렉토리에 저장됩니다: {BASE_OUTPUT_DIR}")

    def handle_event(cpu, data, size):
        global global_counter
        
        event = b["events"].event(data)
        proc_name_raw = event.comm.decode("utf-8", "replace")
        proc_name = proc_name_raw.replace('/', '_').replace(' ', '_').replace('.', '_')
        exe_file = event.filename.decode("utf-8", "replace")
        pid = event.pid
        
        current_time = datetime.now()
        timestamp_str = current_time.strftime("%Y%m%d%H%M%S")

        with counter_lock:
            sequence_num = next(global_counter)
        
        event_output_dir_name = f"{proc_name}_{timestamp_str}_{sequence_num:04d}"
        event_output_dir = os.path.join(BASE_OUTPUT_DIR, event_output_dir_name)
        
        try:
            os.makedirs(event_output_dir, exist_ok=False)
            print(f"[{current_time.strftime('%H:%M:%S')}] [실행 감지] {proc_name} (PID={pid}). 출력 폴더 생성 → {event_output_dir}")
        except FileExistsError:
            print(f"[!] 폴더 생성 충돌 감지: {event_output_dir}")
            return
        except Exception as e:
            print(f"[!] 폴더 생성 실패: {e}")
            return


        runtime_sbom = new_sbom()
        seen = set()
        
        # 2. 실행된 바이너리 자체 component 추가
        main_purl = f"pkg:generic/{proc_name_raw}?pid={pid}&exe={exe_file}"
        if main_purl not in seen:
            runtime_sbom["components"].append({
                "type": "application",
                "name": proc_name_raw,
                "version": "runtime",
                "purl": main_purl,
                "properties": [{"name": "file_path", "value": exe_file}]
            })
            seen.add(main_purl)

        # 3. 로드된 라이브러리들도 추가
        libs_info = get_loaded_libs(pid)
        for lib_path, version in libs_info.items():
            lib_name = os.path.basename(lib_path)
            purl = f"pkg:generic/{lib_name}" 
            if purl not in seen:
                runtime_sbom["components"].append({
                    "type": "library",
                    "name": lib_name,
                    "version": version,
                    "purl": purl,
                    "properties": [{"name": "file_path", "value": lib_path}]
                })
                seen.add(purl)

        # 4. 런타임 SBOM 저장
        runtime_sbom_file_name = f"cyclonedx-runtime-sbom.json"
        runtime_sbom_path = os.path.join(event_output_dir, runtime_sbom_file_name)
        
        try:
            with open(runtime_sbom_path, "w", encoding="utf-8") as f:
                json.dump(runtime_sbom, f, indent=2, ensure_ascii=False)
            print(f" 런타임 SBOM 저장 완료: {runtime_sbom_path}")
        except Exception as e:
            print(f"[!] 런타임 SBOM 저장 실패: {e}")

        # 5. syft 실행
        run_syft(exe_file, pid, event_output_dir)

    b["events"].open_perf_buffer(handle_event)

    # *** Ctrl+C를 안정적으로 처리하기 위한 수정 ***
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


if __name__ == "__main__":
    daemon_context = DaemonizeContext()
    
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'foreground':
        print("💡 포그라운드 모드 실행 중 (Ctrl+C로 종료)")
        with daemon_context: 
            main_loop()
    else:
        print("💡 백그라운드 데몬으로 전환 중... 로그: /tmp/runtime_sbom_monitor.log")
        daemonize(daemon_context)
