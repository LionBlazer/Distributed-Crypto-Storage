//! Absolute I/O deadline. Drop disarms and joins its socket watchdog.
use crate::socket::Interrupt;
use std::{
    io,
    net::{Shutdown, TcpStream},
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
enum Target {
    Socket(TcpStream),
    Client(Arc<Interrupt>),
}
impl Target {
    fn expire(&self) {
        match self {
            Self::Socket(socket) => {
                let _ = socket.shutdown(Shutdown::Both);
            }
            Self::Client(interrupt) => interrupt.expire(),
        }
    }
}
/// Ends local connection I/O at an absolute deadline, including partial progress.
/// Cancellable clients latch expiry and wake readiness; the public raw-socket
/// constructor uses shutdown. Drop disarms and joins the watchdog. This guard
/// never stops remote computations or changes application state.
pub struct ConnectionDeadline {
    complete: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}
impl ConnectionDeadline {
    pub fn new(socket: &TcpStream, budget: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"))?;
        Self::start(Target::Socket(socket.try_clone()?), deadline)
    }
    pub(crate) fn interrupt(signal: Arc<Interrupt>, budget: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"))?;
        Self::start(Target::Client(signal), deadline)
    }
    fn start(target: Target, deadline: Instant) -> io::Result<Self> {
        let complete = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = complete.clone();
        let worker = thread::Builder::new()
            .name("dcs-io-deadline".into())
            .spawn(move || {
                let (lock, wake) = &*signal;
                let Ok(mut done) = lock.lock() else {
                    target.expire();
                    return;
                };
                while !*done {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        target.expire();
                        return;
                    };
                    match wake.wait_timeout(done, remaining) {
                        Ok((next, _)) => done = next,
                        Err(_) => {
                            target.expire();
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
    fn client_deadline_expires_during_progress_and_disarm_preserves_io() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.set_nodelay(true).unwrap();
        server
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut client = crate::socket::Socket::new(client).unwrap();
        client.set_io_timeout(Duration::from_secs(2)).unwrap();
        let disarmed =
            ConnectionDeadline::interrupt(client.interrupt(), Duration::from_secs(30)).unwrap();
        drop(disarmed);
        server.write_all(&[7]).unwrap();
        let mut byte = [0];
        client.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [7]);
        let _deadline =
            ConnectionDeadline::interrupt(client.interrupt(), Duration::from_millis(100)).unwrap();
        let (stop, pace) = mpsc::channel();
        struct Stop(mpsc::Sender<()>);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        thread::scope(|scope| {
            // Release before implicit joins, including on assertion failure.
            let stop = Stop(stop);
            let writer = scope.spawn(move || {
                for _ in 0..32 {
                    if server.write_all(&[1]).is_err()
                        || !matches!(
                            pace.recv_timeout(Duration::from_millis(10)),
                            Err(mpsc::RecvTimeoutError::Timeout)
                        )
                    {
                        return;
                    }
                }
                let _ = pace.recv_timeout(Duration::from_secs(2));
            });
            let started = Instant::now();
            let mut received = 0;
            let error = loop {
                match client.read_exact(&mut byte) {
                    Ok(()) => {
                        received += 1;
                        assert_eq!(byte, [1]);
                    }
                    Err(error) => break error,
                }
            };
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(received >= 2, "Actual byte progress must precede expiry");
            assert!(started.elapsed() < Duration::from_secs(1));
            drop(stop);
            writer.join().unwrap();
        });
    }
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
