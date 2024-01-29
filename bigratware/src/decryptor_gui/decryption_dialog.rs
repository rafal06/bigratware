extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use std::cell::RefCell;
use std::path::PathBuf;
use std::thread;
use anyhow::{Context, Result};
use nwg::NativeUi;
use nwd::NwgUi;
use crate::decryptor::{decode_pair_base64, decrypt_recursive};

#[derive(Default, NwgUi)]
pub struct DecryptionDialog {
    #[nwg_control(
        title: "Decrypting…",
        size: (370, 150),
        center: true,
        flags: "WINDOW|VISIBLE",
    )]
    #[nwg_events(
        OnWindowClose: [DecryptionDialog::on_close],
        OnInit: [DecryptionDialog::on_init])
    ]
    window: nwg::Window,

    #[nwg_control]
    #[nwg_events(OnNotice: [DecryptionDialog::on_notice])]
    notice: nwg::Notice,
    decryption_thread: RefCell<Option<thread::JoinHandle<Result<()>>>>,
    decrypted_pair_b64: String,
    working_path: PathBuf,
    decryption_result: RefCell<Option<Result<()>>>,

    #[nwg_control(
        text: "Decrypting your files…",
        position: (20, 20),
        size: (330, 50),
    )]
    text: nwg::Label,

    #[nwg_control(
        position: (20, 60),
        size: (330, 30),
        flags: "VISIBLE|MARQUEE",
        marquee: true,
    )]
    progress_bar: nwg::ProgressBar,
}

impl DecryptionDialog {

    /// Create the dialog UI on a new thread. The dialog result will be returned by the thread handle.
    /// To alert the main GUI that the dialog completed, this function takes a notice sender object.
    pub fn open(
        sender: nwg::NoticeSender,
        decrypted_pair_b64: String,
        working_path: PathBuf,
    ) -> thread::JoinHandle<Result<()>> {
        thread::spawn(move || -> Result<()> {
            let window = Self::build_ui(Self {
                decrypted_pair_b64,
                working_path,
                ..Default::default()
            }).with_context(|| "Failed to build dialog UI")?;

            nwg::dispatch_thread_events();
            sender.notice();

            window.decryption_result.take().unwrap()
        })
    }

    fn on_init(&self) {
        let sender = self.notice.sender();
        let decrypted_pair_b64 = self.decrypted_pair_b64.clone();
        let working_path = self.working_path.clone();
        *self.decryption_thread.borrow_mut() = Some(thread::spawn(move || -> Result<()> {
            let (key, nonce) = match decode_pair_base64(&decrypted_pair_b64) {
                Ok(pair) => pair,
                Err(err) => return Err(err),
            };

            // TODO: check if the pair matches with what is in the status file

            if let Err(err) = decrypt_recursive(
                &working_path,
                &key,
                &nonce,
            ) {
                sender.notice();
                return Err(err);
            };
            sender.notice();
            Ok(())
        }));
    }

    fn on_notice(&self) {
        *self.decryption_result.borrow_mut() = Some(self.decryption_thread.take().unwrap().join().unwrap());
        let result = self.decryption_result.borrow();
        self.text.set_text(match result.as_ref().unwrap() {
            Ok(_) => "Decryption finished successfully!",
            Err(err) => format!("Error decrypting files: {}", err),
        });
    }

    fn on_close(&self) {
        if self.decryption_result.borrow().is_some() {
            nwg::stop_thread_dispatch();
        }
    }
}
