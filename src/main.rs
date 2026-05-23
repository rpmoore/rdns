use rdns::protocol::Message;

fn main() {
    println!("Hello, world!");
    let dns_message = [0u8; 12];
    let _r = Message::parse(&dns_message);
}
