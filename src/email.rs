use std::env;

use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;

pub fn send_email(message: &Message) {
    let creds = Credentials::new(
        env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
        env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
    );

    let server = env::var("SMTP_SERVER").expect("SMTP_SERVER must be set");

    let mailer = SmtpTransport::builder_dangerous(server)
        .port(
            env::var("SMTP_PORT")
                .expect("SMTP_PORT must be set")
                .parse()
                .unwrap(),
        )
        .credentials(creds)
        .build();

    match mailer.send(message) {
        Ok(_) => println!("Email sent"),
        Err(e) => println!("Error: {}", e),
    }
}
