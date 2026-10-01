//! Explicit terminal or single-line stdin credential input.

mod terminal;

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{FromRawFd, OwnedFd};

const MAX_TOKEN_LENGTH: usize = 512;

fn read_line(reader: &mut impl Read) -> io::Result<String> {
    let mut value = Vec::with_capacity(64);
    while value.len() <= MAX_TOKEN_LENGTH {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => value.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if value.last() == Some(&b'\r') {
        value.pop();
    }
    String::from_utf8(value)
        .map_err(|_| io::Error::other("The delegation token contains invalid characters"))
}

fn validate(token: String) -> io::Result<String> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_LENGTH
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(io::Error::other(
            "The delegation token is empty, too long, or contains invalid characters",
        ));
    }
    Ok(token)
}

fn duplicate_fd(fd: i32) -> io::Result<OwnedFd> {
    // SAFETY: fcntl validates the fd without taking ownership. Only its fresh,
    // successful duplicate becomes an OwnedFd.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this function.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

pub(super) fn read(token_stdin: bool) -> io::Result<String> {
    let token = if token_stdin {
        // Buffering could consume command input after the token's newline.
        // The duplicate shares stdin's position and closes before command exec.
        read_line(&mut File::from(duplicate_fd(libc::STDIN_FILENO)?))?
    } else {
        terminal::read().map_err(|_| {
            io::Error::other(
                "A controlling terminal is required; use --token-stdin for noninteractive input",
            )
        })?
    };
    validate(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn token_line_preserves_command_stdin() {
        let mut input = Cursor::new(b"dst_secret\r\nchild-input\n");
        assert_eq!(read_line(&mut input).unwrap(), "dst_secret");
        let mut remaining = String::new();
        input.read_to_string(&mut remaining).unwrap();
        assert_eq!(remaining, "child-input\n");
    }

    #[test]
    fn token_input_is_bounded_and_validated() {
        let mut input = Cursor::new(vec![b'x'; 1024]);
        assert!(validate(read_line(&mut input).unwrap()).is_err());
        assert!(
            input.position() <= MAX_TOKEN_LENGTH as u64 + 2,
            "oversized token consumed unbounded input"
        );
        for token in ["", "two words", "abc\0def", "nonascii-ї"] {
            assert!(validate(token.into()).is_err());
        }
        assert_eq!(validate("dst_secret".into()).unwrap(), "dst_secret");
    }
}
