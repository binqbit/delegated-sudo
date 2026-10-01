//! Establish hidden input before publishing the prompt. rpassword prints its
//! prompt before disabling echo, which can expose fast input through sudo's PTY.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

struct HiddenInput {
    terminal: File,
    original: libc::termios,
}

impl HiddenInput {
    fn new(terminal: File) -> io::Result<Self> {
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: the open terminal owns its descriptor; original is valid
        // writable storage for the attributes initialized by tcgetattr.
        if unsafe { libc::tcgetattr(terminal.as_raw_fd(), original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: tcgetattr succeeded and initialized original.
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        // SAFETY: hidden is initialized and the owned descriptor is open.
        if unsafe { libc::tcsetattr(terminal.as_raw_fd(), libc::TCSANOW, &hidden) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { terminal, original })
    }
}

impl Drop for HiddenInput {
    fn drop(&mut self) {
        // SAFETY: the terminal is still owned and open until this destructor
        // returns. Restore the full saved state on normal and error exits.
        unsafe {
            libc::tcsetattr(self.terminal.as_raw_fd(), libc::TCSANOW, &self.original);
        }
    }
}

fn with_hidden_input(
    terminal: File,
    prompt_and_read: impl FnOnce() -> io::Result<String>,
) -> io::Result<String> {
    let _hidden = HiddenInput::new(terminal)?;
    prompt_and_read()
}

pub(super) fn read() -> io::Result<String> {
    with_hidden_input(File::open("/dev/tty")?, || {
        // rpassword's inner guard now saves an already-hidden state. It cannot
        // re-enable echo before this outer guard restores the original mode.
        rpassword::prompt_password("Delegation token: ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    fn attributes(terminal: &File) -> libc::termios {
        let mut value = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: value points to writable termios storage; terminal is open.
        assert_eq!(
            unsafe { libc::tcgetattr(terminal.as_raw_fd(), value.as_mut_ptr()) },
            0
        );
        // SAFETY: successful tcgetattr initialized value.
        unsafe { value.assume_init() }
    }

    fn pair_with_echo() -> (File, File) {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: output pointers are valid and optional arguments are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: successful openpty returned two new descriptors we own.
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        let mut original = attributes(&slave);
        original.c_lflag |= libc::ECHO;
        // SAFETY: slave is open and original is an initialized termios value.
        assert_eq!(
            unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &original) },
            0
        );
        (master, slave)
    }

    #[test]
    fn echo_is_disabled_before_prompt_callback_and_restored_after_success() {
        let (master, slave) = pair_with_echo();
        let original = attributes(&master);
        with_hidden_input(slave, || {
            assert_eq!(attributes(&master).c_lflag & libc::ECHO, 0);
            Ok("test-value".into())
        })
        .unwrap();
        assert_eq!(attributes(&master).c_lflag, original.c_lflag);
    }

    #[test]
    fn terminal_modes_are_restored_when_prompt_or_read_fails() {
        let (master, slave) = pair_with_echo();
        let original = attributes(&master);
        let result = with_hidden_input(slave, || {
            assert_eq!(attributes(&master).c_lflag & libc::ECHO, 0);
            Err(io::Error::other("simulated prompt/read failure"))
        });
        assert!(result.is_err());
        let restored = attributes(&master);
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_iflag, original.c_iflag);
        assert_eq!(restored.c_oflag, original.c_oflag);
        assert_eq!(restored.c_cflag, original.c_cflag);
        assert_eq!(restored.c_cc, original.c_cc);
    }
}
