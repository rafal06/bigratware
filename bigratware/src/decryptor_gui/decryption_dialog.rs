extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use std::cell::RefCell;
use std::thread;
use anyhow::Context;
use nwg::NativeUi;
use nwd::NwgUi;

#[derive(Default, NwgUi)]
pub struct DecryptionDialog {
    #[nwg_control(
        title: "Decrypting…",
        size: (370, 150),
        center: true,
        flags: "WINDOW|VISIBLE",
    )]
    #[nwg_events(OnWindowClose: [nwg::stop_thread_dispatch()])] // TODO: temporary, remove later
    window: nwg::Window,

    decryption_thread: RefCell<Option<thread::JoinHandle<String>>>,

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
    pub fn open(sender: nwg::NoticeSender) -> thread::JoinHandle<String> {
        thread::spawn(move || {
            let _app = Self::build_ui(Default::default())
                .with_context(|| "Failed to build dialog UI");

            nwg::dispatch_thread_events();
            sender.notice();

            "Wszystko git mordo".to_owned()
        })
    }
}
