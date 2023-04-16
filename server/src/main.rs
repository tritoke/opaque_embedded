#![no_std]
#![no_main]
#![feature(type_alias_impl_trait, alloc_error_handler)]

use alloc_cortex_m::CortexMHeap;

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

use core::alloc::Layout;
use core::fmt::Write as _;
use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::time::Hertz;
use embassy_stm32::usart::{Config, Uart, UartRx};
use embassy_stm32::{interrupt, peripherals};
use embassy_time::{Duration, Instant};
use heapless::String;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use {defmt_rtt as _, panic_probe as _};

use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use serde::Deserialize;

struct DefaultCs;
impl CipherSuite for DefaultCs {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

const RECV_BUF_LEN: usize = 1024;

/// Writing to a heapless::String then sending and clearing is annoying
macro_rules! fmt_log {
    (ERROR, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::error!("{}", $s.as_str());
        $s.clear();
    };
    (WARN, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::warn!("{}", $s.as_str());
        $s.clear();
    };
    (INFO, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::info!("{}", $s.as_str());
        $s.clear();
    };
    (DEBUG, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::debug!("{}", $s.as_str());
        $s.clear();
    };
    (TRACE, $s:ident, $($arg:tt)*) => {
        core::write!($s, $($arg)*).ok();
        defmt::trace!("{}", $s.as_str());
        $s.clear();
    };
}

/// function like macro to wrap sending data over USART2, returns the number of bytes sent
macro_rules! send {
    ($tx:ident, $buf:ident, $msg:ident) => {{
        let serialised = postcard::to_slice_cobs(&$msg, &mut $buf).unwrap();
        unwrap!($tx.write(&serialised).await);
        serialised.len()
    }};
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) -> ! {
    let mut rcc_config: embassy_stm32::rcc::Config = Default::default();
    rcc_config.sys_ck = Some(Hertz::mhz(84));
    let mut board_config: embassy_stm32::Config = Default::default();
    board_config.rcc = rcc_config;
    let p = embassy_stm32::init(board_config);
    info!("Initialised peripherals.");

    // Initialize the allocator
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1024;
        static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { ALLOCATOR.init(HEAP.as_ptr() as usize, HEAP_SIZE) }
    }
    info!("Initialised heap.");

    // configure USART2 which goes over the USB port on this board
    let mut config = Config::default();
    config.baudrate = 28800;
    let irq = interrupt::take!(USART2);
    let (mut tx, rx) =
        Uart::new(p.USART2, p.PA3, p.PA2, irq, p.DMA1_CH6, p.DMA1_CH5, config).split();
    info!("Configured USART2.");

    // configure the RNG, kind of insecure but this is just a demo and I don't have real entropy
    let now = Instant::now().as_ticks();
    let mut rng = ChaCha8Rng::seed_from_u64(now);
    info!("Seeded RNG - seed = {}", now);

    // setup our OPAQUE server
    let server_setup = ServerSetup::<DefaultCs>::new(&mut rng);
    info!("Created the ServerSetup object.");

    // create something to receive messages
    let mut buf = [0u8; 1024];
    let mut receiver = MsgReceiver::new(rx);
    let mut s: String<1024> = String::new();
    info!("Receiver and buffers set up");

    // wait for a user to register themselves
    let password_file = loop {
        info!("Waiting for a registration packet.");
        let registration_request: RegistrationRequest<DefaultCs> = loop {
            match receiver.recv_msg().await {
                Ok(req) => {
                    fmt_log!(DEBUG, s, "Received RegistrationRequest - {req:?}");
                    break req;
                }
                Err(e) => {
                    fmt_log!(ERROR, s, "Received Error - {e:?}");
                    continue;
                }
            };
        };
        info!("Received RegistrationRequest.");

        let start_result = ServerRegistration::<DefaultCs>::start(
            &server_setup,
            registration_request,
            b"tritoke@kiss.the.homies.goodnight",
        );
        let message = match start_result {
            Ok(inner) => inner.message,
            Err(e) => {
                fmt_log!(ERROR, s, "ServerRegistration::start returned error={e:?}");
                continue;
            }
        };
        info!("Sending RegistrationRequest.");
        send!(tx, buf, message);

        let registration_upload: RegistrationUpload<DefaultCs> = match receiver.recv_msg().await {
            Ok(req) => {
                fmt_log!(DEBUG, s, "Received RegistrationUpload - {req:?}");
                req
            }
            Err(e) => {
                fmt_log!(ERROR, s, "Received Error - {e:?}");
                continue;
            }
        };
        info!("Received RegistrationUpload from user, finishing registration.");

        break ServerRegistration::<DefaultCs>::finish(registration_upload);
    };

    // perform an actual login
    loop {
        info!("Now accepting logins :)");
        let mut time_taken: Duration = Default::default();
        let mut bytes_sent = 0;

        // receive client's login
        let cred_req: CredentialRequest<DefaultCs> = match receiver.recv_msg().await {
            Ok(req) => {
                fmt_log!(DEBUG, s, "Received CredentialRequest - {req:?}");
                req
            }
            Err(e) => {
                fmt_log!(ERROR, s, "Received Error - {e:?}");
                continue;
            }
        };
        info!("Received CredentialRequest.");

        let start = Instant::now();
        let server_login_start_result = ServerLogin::start(
            &mut rng,
            &server_setup,
            Some(password_file.clone()),
            cred_req,
            b"tritoke@kiss.the.homies.goodnight",
            ServerLoginStartParameters::default(),
        );
        time_taken += Instant::now().duration_since(start);

        let (message, server_login) = match server_login_start_result {
            Ok(inner) => (inner.message, inner.state),
            Err(e) => {
                fmt_log!(ERROR, s, "ServerLogin::start returned error={e:?}");
                continue;
            }
        };
        info!("Sending CredentialResponse.");
        bytes_sent += send!(tx, buf, message);

        let cred_fin: CredentialFinalization<DefaultCs> = match receiver.recv_msg().await {
            Ok(req) => {
                fmt_log!(DEBUG, s, "Received CredentialFinalization - {req:?}");
                req
            }
            Err(e) => {
                fmt_log!(ERROR, s, "Received Error - {e:?}");
                continue;
            }
        };
        info!("Received CredentialFinalization.");
        let start = Instant::now();
        let cred_fin_result = server_login.finish(cred_fin);
        time_taken += Instant::now().duration_since(start);
        let session_key = match cred_fin_result {
            Ok(inner) => inner.session_key,
            Err(e) => {
                fmt_log!(ERROR, s, "Received Error - {e:?}");
                continue;
            }
        };

        info!("Derived final key: {:02X}", session_key.as_slice());
        info!("Total bytes sent: {}", bytes_sent);
        info!(
            "Total computation time: {}ms - {} ticks",
            time_taken.as_millis(),
            time_taken.as_ticks()
        );
    }
}

struct MsgReceiver<'uart> {
    buf: [u8; RECV_BUF_LEN],
    idx: usize,
    rx: UartRx<'uart, peripherals::USART2, peripherals::DMA1_CH5>,
    reset_pos: Option<usize>,
}

impl<'uart> MsgReceiver<'uart> {
    fn new(rx: UartRx<'uart, peripherals::USART2, peripherals::DMA1_CH5>) -> Self {
        Self {
            buf: [0u8; 1024],
            idx: 0,
            rx,
            reset_pos: None,
        }
    }

    async fn recv_msg<T: for<'a> Deserialize<'a>>(&mut self) -> postcard::Result<T> {
        // reset the state
        // copy all the data we read after the 0 byte to the start of the self.buffer
        if let Some(zi) = self.reset_pos {
            self.buf.copy_within(zi + 1..self.idx, 0);
            self.idx = self.idx.saturating_sub(zi + 1);
            self.reset_pos = None;
        }

        // if there is a zero in the message buffer try to process that msg
        let previous_msg_zi = self.buf[..self.idx].iter().position(|x| *x == 0);

        let zi = loop {
            if let Some(zi) = previous_msg_zi {
                break zi;
            }

            // read as much as we can off the wire
            let count = unwrap!(self.rx.read_until_idle(&mut self.buf[self.idx..]).await);
            let zero_idx = if count == 0 {
                continue;
            } else {
                // log that we managed to read some data
                trace!(
                    "Read {} bytes - {:02X}",
                    count,
                    self.buf[self.idx..self.idx + count],
                );

                // update state
                self.idx += count;

                // calculate the index of zero in the self.buffer
                // it is tempting to optimise this to just what is read but more than one packet can
                // be read at once so the whole buffer needs to be searched to allow for this behaviour
                let zero_idx = self.buf[..self.idx].iter().position(|x| *x == 0);

                zero_idx
            };

            let Some(zi) = zero_idx else {
                if self.idx == RECV_BUF_LEN {
                    self.idx = 0;
                    warn!("Weird state encountered - filled entire self.buffer without finding message.");
                }

                continue;
            };

            break zi;
        };

        trace!("self.buf[..self.idx] = {:02X}", self.buf[..self.idx]);
        trace!(
            "Found zero byte at index {} - {} - {}",
            zi,
            self.buf[zi],
            self.idx
        );

        // store zi for next time
        self.reset_pos = Some(zi);

        // parse the result
        postcard::from_bytes_cobs(&mut self.buf[..=zi])
    }
}

#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    error!("Hit OOM Handler :(");
    loop {}
}
