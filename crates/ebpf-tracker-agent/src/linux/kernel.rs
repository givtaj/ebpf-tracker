use std::ffi::CStr;
use std::io;

const REGRESSION: &str = "https://github.com/actions/runner-images/issues/15003";

pub(super) fn check_host() -> Result<(), String> {
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut name) } < 0 {
        return Err(format!(
            "cannot inspect host kernel: {}",
            io::Error::last_os_error()
        ));
    }
    let release = unsafe { CStr::from_ptr(name.release.as_ptr()) }.to_string_lossy();
    check_release(&release)
}

fn check_release(release: &str) -> Result<(), String> {
    // This exact host release is confirmed to silently skip syscall events on
    // CPUs other than CPU 0. Do not infer support from nearby version numbers.
    if release == "7.0.0-1017-azure" {
        return Err(format!(
            "host kernel {release} has a confirmed syscall tracing regression that silently loses events; use a fixed host kernel or the unaffected 6.17 Azure kernel before capturing (changing the container image does not change its host kernel). Details: {REGRESSION}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_confirmed_kernel_regression_with_actionable_error() {
        let error = check_release("7.0.0-1017-azure").unwrap_err();
        assert!(error.contains("silently loses events"));
        assert!(error.contains("fixed host kernel"));
        assert!(error.contains(REGRESSION));
    }

    #[test]
    fn permits_observed_linuxkit_and_previous_azure_releases() {
        for release in ["7.0.14-linuxkit", "7.0.14", "6.17.0-1022-azure"] {
            assert!(check_release(release).is_ok(), "{release}");
        }
    }
}
