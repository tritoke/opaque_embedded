use anyhow::{anyhow, Result};
use clap::Parser;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult,
    ClientLoginStartResult, ClientRegistration, ClientRegistrationFinishParameters,
    ClientRegistrationFinishResult, ClientRegistrationStartResult, CredentialResponse,
    RegistrationResponse,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serialport::{SerialPort, SerialPortType};
use std::io;
use std::time::{Duration, Instant};

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

const USART_BAUD: u32 = 28800;
const RECV_BUF_LEN: usize = 1024;

struct Default;
impl CipherSuite for Default {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the USB port to open
    #[arg(long)]
    port: Option<String>,

    /// List USB ports on the system
    #[arg(long)]
    list_ports: bool,

    /// The maximum log level
    #[arg(long, default_value_t = tracing::Level::INFO)]
    log_level: tracing::Level,

    /// Skip perform registration before AuCPace
    #[arg(long)]
    skip_register: bool,

    /// The Username to perform the exchange with
    #[arg(long, short)]
    username: String,

    /// The Password to perform the exchange with
    #[arg(long, short)]
    password: String,
}

fn main() -> Result<()> {
    let args = Args::try_parse()?;

    // setup the logger
    tracing_subscriber::fmt()
        .with_ansi(true)
        .with_max_level(args.log_level)
        .with_writer(io::stderr)
        .init();

    debug!("args={args:?}");

    // list the ports if the user asks for it
    if args.list_ports {
        let mut ports = serialport::available_ports()?;
        ports.retain(|port| matches!(port.port_type, SerialPortType::UsbPort(_)));
        println!("Found the following USB ports:");
        for port in ports {
            println!("{}", port.port_name);
        }

        return Ok(());
    }

    // open the serial port connection
    let port_name = args
        .port
        .ok_or_else(|| anyhow!("Must supply a USB port."))?;
    let mut serial_port = serialport::new(port_name, USART_BAUD)
        .timeout(Duration::from_millis(500))
        .open()?;
    let serial = serial_port.as_mut();
    info!("Opened serial port connection.");

    // perform registration
    let _user = args.username.as_bytes();
    let pass = args.password.as_bytes();
    let mut client_rng = OsRng;
    if !args.skip_register {
        let ClientRegistrationStartResult {
            message,
            state: client_registration,
        } = ClientRegistration::<Default>::start(&mut client_rng, pass)?;

        // send client registration
        let _ = send(serial, &message)?;
        info!("Sent registration request");

        // receive registration response
        let reg_resp: RegistrationResponse<Default> = recv(serial)?;
        info!("Received registration response");

        // finish registration
        let ClientRegistrationFinishResult { message, .. } = client_registration.finish(
            &mut client_rng,
            pass,
            reg_resp,
            ClientRegistrationFinishParameters::default(),
        )?;
        let _ = send(serial, &message)?;
        info!("Sent registration upload");
    }

    // start login
    info!("Beginning Client login");
    let mut bytes_sent = 0;
    let start = Instant::now();

    let ClientLoginStartResult {
        message,
        state: client_login,
    } = ClientLogin::<Default>::start(&mut client_rng, pass)?;
    bytes_sent += send(serial, &message)?;
    info!("Sent credential request");

    let cred_resp: CredentialResponse<Default> = recv(serial)?;
    info!("Received credential response");

    let ClientLoginFinishResult {
        message,
        session_key,
        ..
    } = client_login.finish(pass, cred_resp, ClientLoginFinishParameters::default())?;

    info!("Computed session key, sending CredentialFinalization to the server");
    bytes_sent += send(serial, &message)?;

    info!("Derived final key: {:02X?}", session_key.as_slice());
    info!("Total bytes sent: {}", bytes_sent);
    info!(
        "Derived final key in {}ms",
        Instant::now().duration_since(start).as_millis()
    );

    Ok(())
}

/// send data using postcard to serialize
fn send<T: Serialize>(tx: &mut dyn SerialPort, obj: &T) -> Result<usize> {
    let ser = postcard::to_stdvec_cobs(obj)?;
    tx.write_all(&ser)?;
    Ok(ser.len())
}

fn recv<T: for<'a> Deserialize<'a>>(rx: &mut dyn SerialPort) -> Result<T> {
    let mut buf = [0u8; RECV_BUF_LEN];
    let mut idx = 0;
    loop {
        if idx == buf.len() {
            panic!("Reached end of client recv buffer???");
        }

        let bytes_read = rx.read(&mut buf[idx..])?;

        // look for a zero in the bytes read
        if let Some(zi) = buf[idx..idx + bytes_read].iter().position(|x| *x == 0) {
            break postcard::from_bytes_cobs(&mut buf[..zi + idx]).map_err(|e| anyhow!(e));
        }

        idx += bytes_read;
    }
}
