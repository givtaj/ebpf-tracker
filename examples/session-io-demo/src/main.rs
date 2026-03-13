use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

include!(concat!(env!("OUT_DIR"), "/generated_message.rs"));

fn main() {
    let input = fs::read_to_string("input/message.txt").expect("failed to read input/message.txt");

    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind local listener");
    let addr = listener
        .local_addr()
        .expect("failed to resolve local listener address");

    let server = thread::spawn(move || {
        let (mut stream, peer) = listener.accept().expect("failed to accept client");
        let mut request = [0u8; 256];
        let size = stream.read(&mut request).expect("failed to read request");
        let payload = String::from_utf8_lossy(&request[..size]).trim().to_string();
        let response = format!("server saw '{payload}' from {peer}");
        stream
            .write_all(response.as_bytes())
            .expect("failed to write response");
    });

    let mut client = TcpStream::connect(addr).expect("failed to connect to local listener");
    client
        .write_all(input.trim().as_bytes())
        .expect("failed to write to local listener");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("failed to read response");

    server.join().expect("server thread panicked");

    fs::create_dir_all("logs").expect("failed to create logs directory");
    let summary = format!(
        "generated={GENERATED_MESSAGE}\ninput={}\nresponse={}\n",
        input.trim(),
        response.trim()
    );
    fs::write("logs/session-summary.txt", summary)
        .expect("failed to write logs/session-summary.txt");

    println!("{GENERATED_MESSAGE}");
    println!("{}", response.trim());
    println!("wrote logs/session-summary.txt");
}
