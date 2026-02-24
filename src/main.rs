mod dns;

use crate::dns::Message;

fn main()
{
    println!("Hello, world!");
    let dns_message = [0u8; 12];
    let _r = Message::new(&dns_message);
}
