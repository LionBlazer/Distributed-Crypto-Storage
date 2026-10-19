//! Absolute I/O deadline. Drop disarms and joins its socket watchdog.
use std::{
    io,
    net::{Shutdown, TcpStream},
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
/// Shuts this connection's socket when an absolute budget expires, even when
/// partial reads keep progressing. It never stops a remote computation or changes
/// application state. Dropping this guard disarms the watchdog.
pub struct ConnectionDeadline {
    complete: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}
impl ConnectionDeadline {
    pub fn new(socket: &TcpStream, budget: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"))?;
        let socket = socket.try_clone()?;
        let complete = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = complete.clone();
        let worker = thread::Builder::new()
            .name("dcs-io-deadline".into())
            .spawn(move || {
                let (lock, wake) = &*signal;
                let Ok(mut done) = lock.lock() else {
                    let _ = socket.shutdown(Shutdown::Both);
                    return;
                };
                while !*done {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        let _ = socket.shutdown(Shutdown::Both);
                        return;
                    };
                    match wake.wait_timeout(done, remaining) {
                        Ok((next, _)) => done = next,
                        Err(_) => {
                            let _ = socket.shutdown(Shutdown::Both);
                            return;
                        }
                    }
                }
            })?;
        Ok(Self {
            complete,
            worker: Some(worker),
        })
    }
}
impl Drop for ConnectionDeadline {
    fn drop(&mut self) {
        let (lock, wake) = &*self.complete;
        if let Ok(mut done) = lock.lock() {
            *done = true;
            wake.notify_all();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
    };
    #[test]
    fn absolute_deadline_interrupts_progressing_read_and_disarm_preserves_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let disarmed = ConnectionDeadline::new(&client, Duration::from_secs(30)).unwrap();
        drop(disarmed);
        server.write_all(&[7]).unwrap();
        let mut byte = [0];
        client.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [7]);
        let _deadline = ConnectionDeadline::new(&client, Duration::from_millis(100)).unwrap();
        let (stop, pace) = mpsc::channel::<()>();
        let writer = thread::spawn(move || {
            loop {
                if server.write_all(&[1]).is_err() {
                    break;
                }
                // Sustain progress below the inactivity timeout deliberately.
                if pace.recv_timeout(Duration::from_millis(10)).is_ok() {
                    break;
                }
            }
        });
        let started = Instant::now();
        let mut impossible = [0; 4096];
        assert!(client.read_exact(&mut impossible).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = stop.send(());
        writer.join().unwrap();
    }
}
