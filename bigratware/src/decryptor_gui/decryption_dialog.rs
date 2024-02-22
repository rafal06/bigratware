extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use std::cell::RefCell;
use std::path::PathBuf;
use std::thread;
use anyhow::{Context, Result, Error};
use nwg::NativeUi;
use nwd::NwgUi;
use crate::decryptor::{decode_pair_base64, decrypt_recursive, StatusData, verify_supplied_pair};
use crate::startup::remove_self;

#[derive(Debug)]
pub enum DecryptionError {
    PairNotMatching,
    Other(Error),
}

impl From<Error> for DecryptionError {
    fn from(value: Error) -> Self {
        Self::Other(value)
    }
}

#[derive(Default, NwgUi)]
pub struct DecryptionDialog {
    #[nwg_control(
        title: "Decrypting…",
        size: (370, 120),
        center: true,
        flags: "WINDOW|VISIBLE",
    )]
    #[nwg_events(
        OnWindowClose: [DecryptionDialog::on_close(SELF, EVT_DATA)],
        OnInit: [DecryptionDialog::on_init])
    ]
    window: nwg::Window,

    #[nwg_control]
    #[nwg_events(OnNotice: [DecryptionDialog::on_notice])]
    notice: nwg::Notice,
    decryption_thread: RefCell<Option<thread::JoinHandle<Result<(), DecryptionError>>>>,
    decrypted_pair_b64: String,
    working_path: PathBuf,
    status_data: StatusData,
    decryption_result: RefCell<Option<Result<(), DecryptionError>>>,

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

    #[nwg_control(
        text: "Close",
        position: (120, 65),
        size: (130, 30),
        flags: "NONE",
    )]
    #[nwg_events(OnButtonClick: [DecryptionDialog::on_close(SELF, EVT_DATA)])]
    close_button: nwg::Button,
}

impl DecryptionDialog {

    /// Create the dialog UI on a new thread. The dialog result will be returned by the thread handle.
    /// To alert the main GUI that the dialog completed, this function takes a notice sender object.
    pub fn open(
        sender: nwg::NoticeSender,
        decrypted_pair_b64: String,
        working_path: PathBuf,
        status_data: StatusData,
    ) -> thread::JoinHandle<Result<(), DecryptionError>> {
        thread::spawn(move || -> Result<(), DecryptionError> {
            let window = Self::build_ui(Self {
                decrypted_pair_b64,
                working_path,
                status_data,
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
        let encrypted_verify_str = self.status_data.encrypted_verify_str;
        let encrypted_key = self.status_data.encrypted_key;
        *self.decryption_thread.borrow_mut() = Some(thread::spawn(move || -> Result<(), DecryptionError> {
            let (key, nonce) = match decode_pair_base64(&decrypted_pair_b64) {
                Ok(pair) => pair,
                Err(err) => {
                    sender.notice();
                    return Err(DecryptionError::Other(err));
                },
            };

            if !verify_supplied_pair(
                &key,
                &nonce,
                &encrypted_verify_str,
            ) {
                sender.notice();
                return Err(DecryptionError::PairNotMatching);
            }

            if let Err(err) = decrypt_recursive(
                &working_path,
                &key,
                &nonce,
                &encrypted_key,
            ) {
                sender.notice();
                return Err(DecryptionError::Other(err));
            }

            if let Err(err) = remove_self() {
                sender.notice();
                // TODO: Add an error variant for deleting self
                return Err(DecryptionError::Other(err));
            }
            sender.notice();
            Ok(())
        }));
    }

    fn on_notice(&self) {
        *self.decryption_result.borrow_mut() = Some(self.decryption_thread.take().unwrap().join().unwrap());
        let result = self.decryption_result.borrow();
        self.text.set_text(&match result.as_ref().unwrap() {
            Ok(_) => "Decryption finished successfully!".to_owned(),
            Err(err) => {
                match err {
                    DecryptionError::PairNotMatching => "The supplied key is not correct".to_owned(),
                    DecryptionError::Other(err) => format!("Error decrypting files: {err}"),
                }
            },
        });
        self.progress_bar.set_visible(false);
        self.close_button.set_visible(true);
    }

    fn on_close(&self, data: &nwg::EventData) {
        // if the decryption hasn't finished yet
        if match self.decryption_result.try_borrow() {
            Ok(result) => result.is_none(),
            Err(_) => true,
        } {
            if let nwg::EventData::OnWindowClose(close_data) = data {
                close_data.close(false);
            }
        } else {
            nwg::stop_thread_dispatch();
        }
    }
}
