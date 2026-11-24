use std::ffi::{c_char, CStr, CString};
use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::time::Duration;

#[path = "../route.rs"]
mod route;

use route_support::direct_support;

unsafe extern "C" fn write_event(json: *const c_char) {
    if !json.is_null() {
        let event = unsafe { CStr::from_ptr(json) };
        let mut output = io::stdout().lock();
        let _ = output
            .write_all(event.to_bytes())
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.flush());
    }
}

fn watch_control() -> io::Result<()> {
    std::thread::Builder::new()
        .name("direct-control".into())
        .spawn(|| {
            for line in io::stdin().lock().lines() {
                match line {
                    Ok(line) if !line.eq_ignore_ascii_case("stop") => continue,
                    _ => break,
                }
            }
            // EOF may arrive before the native session resets its stop flag.
            loop {
                direct_support::stop();
                std::thread::sleep(Duration::from_millis(20));
            }
        })?;
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref() {
        Some(flag) if flag == "--direct-contract" && args.next().is_none() => {
            println!(
                "direct-config/1 {}",
                option_env!("UAC_DIRECT_SOURCE_ID").unwrap_or("local")
            );
            return Ok(());
        }
        Some(flag) if flag == "--config" => {}
        _ => return Err("usage: uac-direct --config FILE [--control-stdin]".into()),
    }
    let file = args.next().ok_or("--config requires a file")?;
    let control = match args.next() {
        None => false,
        Some(flag) if flag == "--control-stdin" && args.next().is_none() => true,
        _ => return Err("unexpected argument after --config FILE".into()),
    };
    let json = CString::new(std::fs::read(file)?)?;
    direct_support::set_event_callback(Some(write_event));
    if control {
        watch_control()?;
    }
    let code = unsafe {
        direct_support::run_session(json.as_ptr(), None, "UAC Direct", route::run)
    };
    if code != 0 {
        let error = unsafe { CStr::from_ptr(direct_support::last_error()) };
        return Err(error.to_string_lossy().into_owned().into());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
