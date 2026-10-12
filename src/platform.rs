#[cfg(not(windows))]
use std::path::Path;

#[cfg(not(windows))]
use crate::protocol::ProcessSample;

#[cfg(target_os = "linux")]
pub(crate) fn process_sample(pid: u32) -> ProcessSample {
    let mut sample = ProcessSample::default();
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        sample.rss_bytes = status.lines().find_map(|line| {
            let value = line.strip_prefix("VmRSS:")?.split_whitespace().next()?;
            value.parse::<u64>().ok().map(|kilobytes| kilobytes * 1024)
        });
    }
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        && let Some((_, fields)) = stat.rsplit_once(") ")
    {
        let fields = fields.split_whitespace().collect::<Vec<_>>();
        sample.cpu_user = fields.get(11).and_then(|value| value.parse().ok());
        sample.cpu_kernel = fields.get(12).and_then(|value| value.parse().ok());
        sample.start_token = fields.get(19).and_then(|value| value.parse().ok());
    }
    sample
}

#[cfg(target_os = "linux")]
pub(crate) fn process_alive(pid: u32, start_token: Option<u64>) -> bool {
    let sample = process_sample(pid);
    sample.start_token.is_some()
        && start_token.is_none_or(|expected| sample.start_token == Some(expected))
}

#[cfg(target_os = "linux")]
pub(crate) fn write_minidump(_pid: u32, _path: &Path) -> Result<(), String> {
    Err("minidumps are only available on Windows".to_string())
}

#[cfg(target_os = "linux")]
pub(crate) fn install_native_crash_handler(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{
        CloseHandle, FILETIME, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, STILL_ACTIVE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, MINIDUMP_EXCEPTION_INFORMATION,
        MiniDumpNormal, MiniDumpWithThreadInfo, MiniDumpWithUnloadedModules,
        MiniDumpWriteDump, SetUnhandledExceptionFilter,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetExitCodeProcess,
        GetProcessTimes, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    use crate::protocol::ProcessSample;

    struct NativeCrash {
        path: Box<[u16]>,
    }

    static NATIVE_CRASH: OnceLock<NativeCrash> = OnceLock::new();

    pub(crate) fn process_sample(pid: u32) -> ProcessSample {
        let access = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
        let process = unsafe { OpenProcess(access, 0, pid) };
        if process.is_null() {
            return ProcessSample::default();
        }
        let mut sample = ProcessSample::default();
        let mut memory = PROCESS_MEMORY_COUNTERS {
            cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        if unsafe {
            GetProcessMemoryInfo(
                process,
                &mut memory,
                size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            )
        } != 0
        {
            sample.rss_bytes = Some(memory.WorkingSetSize as u64);
        }
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe {
            GetProcessTimes(
                process,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } != 0
        {
            sample.start_token = Some(filetime(created));
            sample.cpu_kernel = Some(filetime(kernel));
            sample.cpu_user = Some(filetime(user));
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process, &mut exit_code) } != 0
            && exit_code != STILL_ACTIVE as u32
        {
            sample.exit_code = Some(exit_code);
        }
        unsafe {
            CloseHandle(process);
        }
        sample
    }

    pub(crate) fn process_alive(pid: u32, start_token: Option<u64>) -> bool {
        let sample = process_sample(pid);
        sample.start_token.is_some()
            && sample.exit_code.is_none()
            && start_token.is_none_or(|expected| sample.start_token == Some(expected))
    }

    pub(crate) fn write_minidump(pid: u32, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                0,
                pid,
            )
        };
        if process.is_null() {
            return Err(format!("open process {pid} for minidump failed"));
        }
        let result = write_dump_handle(process, pid, path, ptr::null());
        unsafe {
            CloseHandle(process);
        }
        result
    }

    pub(crate) fn install_native_crash_handler(path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let wide = wide_path(path);
        NATIVE_CRASH
            .set(NativeCrash { path: wide })
            .map_err(|_| "native crash handler already installed".to_string())?;
        unsafe {
            SetUnhandledExceptionFilter(Some(native_exception_filter));
        }
        Ok(())
    }

    unsafe extern "system" fn native_exception_filter(info: *const EXCEPTION_POINTERS) -> i32 {
        if let Some(config) = NATIVE_CRASH.get() {
            let file = unsafe {
                CreateFileW(
                    config.path.as_ptr(),
                    GENERIC_WRITE,
                    FILE_SHARE_READ,
                    ptr::null(),
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    ptr::null_mut(),
                )
            };
            if file != INVALID_HANDLE_VALUE {
                let exception = MINIDUMP_EXCEPTION_INFORMATION {
                    ThreadId: unsafe { GetCurrentThreadId() },
                    ExceptionPointers: info.cast_mut(),
                    ClientPointers: 0,
                };
                let dump_type = MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules;
                let _ = unsafe {
                    MiniDumpWriteDump(
                        GetCurrentProcess(),
                        GetCurrentProcessId(),
                        file,
                        dump_type,
                        &exception,
                        ptr::null(),
                        ptr::null(),
                    )
                };
                unsafe {
                    CloseHandle(file);
                }
            }
        }
        EXCEPTION_CONTINUE_SEARCH
    }

    fn write_dump_handle(
        process: HANDLE,
        pid: u32,
        path: &Path,
        exception: *const MINIDUMP_EXCEPTION_INFORMATION,
    ) -> Result<(), String> {
        let wide = wide_path(path);
        let file = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                ptr::null(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if file == INVALID_HANDLE_VALUE {
            return Err(format!("create minidump {} failed", path.display()));
        }
        let dump_type = MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules;
        let ok = unsafe {
            MiniDumpWriteDump(
                process,
                pid,
                file,
                dump_type,
                exception,
                ptr::null(),
                ptr::null(),
            )
        };
        unsafe {
            CloseHandle(file);
        }
        if ok == 0 {
            Err(format!("write minidump {} failed", path.display()))
        } else {
            Ok(())
        }
    }

    fn filetime(value: FILETIME) -> u64 {
        (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
    }

    fn wide_path(path: &Path) -> Box<[u16]> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

#[cfg(windows)]
pub(crate) use windows::{
    install_native_crash_handler, process_alive, process_sample, write_minidump,
};

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn process_sample(_pid: u32) -> ProcessSample {
    ProcessSample::default()
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn process_alive(_pid: u32, _start_token: Option<u64>) -> bool {
    false
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn write_minidump(_pid: u32, _path: &Path) -> Result<(), String> {
    Err("minidumps are unsupported on this platform".to_string())
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(crate) fn install_native_crash_handler(_path: &Path) -> Result<(), String> {
    Ok(())
}
