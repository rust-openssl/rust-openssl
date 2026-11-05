use std::collections::VecDeque;
use std::io::{self, Read, Write};

use crate::ssl::{
    ErrorCode, Ssl, SslContext, SslFiletype, SslMethod, SslStream, SslVerifyMode, SslVersion,
};

#[derive(Debug, Default)]
struct FlushStream {
    incoming: VecDeque<u8>,
    outgoing: Vec<u8>,
    flush_errors: VecDeque<io::ErrorKind>,
    flush_calls: usize,
    read_error: Option<io::ErrorKind>,
    write_error: Option<io::ErrorKind>,
}

impl Read for FlushStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(kind) = self.read_error.take() {
            return Err(io::Error::new(kind, "injected read error"));
        }
        if self.incoming.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let len = buf.len().min(self.incoming.len());
        for byte in &mut buf[..len] {
            *byte = self.incoming.pop_front().unwrap();
        }
        Ok(len)
    }
}

impl Write for FlushStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(kind) = self.write_error.take() {
            return Err(io::Error::new(kind, "injected write error"));
        }
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_calls += 1;
        match self.flush_errors.pop_front() {
            Some(kind) => Err(io::Error::new(kind, "injected flush error")),
            None => Ok(()),
        }
    }
}

fn client(errors: &[io::ErrorKind]) -> SslStream<FlushStream> {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    // TLS 1.2 exercises the buffering BIO used during the handshake.
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    ctx.set_ca_file("test/root-ca.pem").unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_connect_state();
    SslStream::new(
        ssl,
        FlushStream {
            flush_errors: errors.iter().copied().collect(),
            ..FlushStream::default()
        },
    )
    .unwrap()
}

fn transfer(from: &mut SslStream<FlushStream>, to: &mut SslStream<FlushStream>) {
    to.get_mut()
        .incoming
        .extend(from.get_mut().outgoing.drain(..));
}

#[test]
fn retryable_flush_completes_handshake() {
    for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::NotConnected] {
        let mut client = client(&[kind, kind]);
        let error = client.do_handshake().unwrap_err();
        assert_eq!(error.code(), ErrorCode::WANT_WRITE);
        assert_eq!(error.io_error().unwrap().kind(), kind);

        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file("test/cert.pem", SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
            .unwrap();
        let mut ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.set_accept_state();
        let mut server = SslStream::new(ssl, FlushStream::default()).unwrap();
        let mut client_done = false;
        let mut server_done = false;
        // Memory I/O and a finite number of steps make failure deterministic,
        // without a network timeout or a blocked server thread.
        for _ in 0..32 {
            transfer(&mut client, &mut server);
            for (stream, done) in [
                (&mut server, &mut server_done),
                (&mut client, &mut client_done),
            ] {
                if !*done {
                    match stream.do_handshake() {
                        Ok(()) => *done = true,
                        Err(error) => assert!(
                            matches!(error.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE),
                            "{error:?}"
                        ),
                    }
                }
            }
            transfer(&mut server, &mut client);
            if client_done && server_done {
                break;
            }
        }
        assert!(client_done && server_done, "handshake did not finish");
        assert!(client.get_ref().flush_calls >= 3);
        assert_eq!(
            client.ssl().verify_result(),
            crate::x509::X509VerifyResult::OK
        );

        let message = b"flush retry round trip";
        client.write_all(message).unwrap();
        transfer(&mut client, &mut server);
        let mut received = vec![0; message.len()];
        server.read_exact(&mut received).unwrap();
        assert_eq!(&received, message);
        server.write_all(&received).unwrap();
        transfer(&mut server, &mut client);
        client.read_exact(&mut received).unwrap();
        assert_eq!(&received, message);
    }
}

fn assert_transport_error(
    error: crate::ssl::Error,
    expected: ErrorCode,
    kind: io::ErrorKind,
    message: &str,
) {
    #[cfg(libressl)]
    if kind == io::ErrorKind::BrokenPipe {
        // LibreSSL adds SSL_R_UNKNOWN for these synthetic BIO failures.
        assert_eq!(error.code(), ErrorCode::SSL);
        assert!(error.io_error().is_none());
        let errors = error.ssl_error().unwrap().errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].library_code(), 20); // ERR_LIB_SSL in LibreSSL's err.h.
        assert_eq!(errors[0].reason_code(), 999); // SSL_R_UNKNOWN in LibreSSL's ssl.h.
        assert!(std::error::Error::source(&error)
            .unwrap()
            .is::<crate::error::ErrorStack>());
        return;
    }

    assert_eq!(error.code(), expected);
    let error = error.into_io_error().unwrap();
    assert_eq!(error.kind(), kind);
    assert_eq!(error.to_string(), message);
}

#[test]
fn hard_flush_error_is_preserved() {
    let mut client = client(&[io::ErrorKind::BrokenPipe]);
    let error = client.do_handshake().unwrap_err();
    assert!(client.get_ref().flush_errors.is_empty());
    assert_transport_error(
        error,
        ErrorCode::SYSCALL,
        io::ErrorKind::BrokenPipe,
        "injected flush error",
    );
}

#[test]
fn hard_flush_error_after_retry_is_not_retryable() {
    let mut client = client(&[io::ErrorKind::WouldBlock, io::ErrorKind::BrokenPipe]);
    let error = client.do_handshake().unwrap_err();
    assert_eq!(error.code(), ErrorCode::WANT_WRITE);
    assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::WouldBlock);
    let error = client.do_handshake().unwrap_err();
    assert!(client.get_ref().flush_errors.is_empty());
    assert_transport_error(
        error,
        ErrorCode::SYSCALL,
        io::ErrorKind::BrokenPipe,
        "injected flush error",
    );
}

#[test]
fn non_flush_io_errors_keep_their_classification() {
    for kind in [
        io::ErrorKind::WouldBlock,
        io::ErrorKind::NotConnected,
        io::ErrorKind::BrokenPipe,
    ] {
        let mut reader = client(&[]);
        reader.get_mut().read_error = Some(kind);
        let error = reader.do_handshake().unwrap_err();
        let expected = if kind == io::ErrorKind::BrokenPipe {
            ErrorCode::SYSCALL
        } else {
            ErrorCode::WANT_READ
        };
        assert!(reader.get_ref().read_error.is_none());
        assert_transport_error(error, expected, kind, "injected read error");

        let mut writer = client(&[]);
        writer.get_mut().write_error = Some(kind);
        let error = writer.do_handshake().unwrap_err();
        let expected = if kind == io::ErrorKind::BrokenPipe {
            ErrorCode::SYSCALL
        } else {
            ErrorCode::WANT_WRITE
        };
        assert!(writer.get_ref().write_error.is_none());
        assert_transport_error(error, expected, kind, "injected write error");
    }
}
