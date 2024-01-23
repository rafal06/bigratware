extern crate native_windows_gui as nwg;
extern crate native_windows_derive as nwd;

use anyhow::{Context, Result};
use nwd::NwgUi;
use nwg::{Font, NativeUi};
use indoc::indoc;

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
    #[nwg_events(OnWindowClose: [nwg::stop_thread_dispatch()])]
    window: nwg::Window,

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
            \r
            Your important files are encrypted.\r
            Many of your documents, photos, videos, databases and other files are no longer accessible because they \
            have been encrypted. Maybe you are busy looking for a way to recover your files, but do not waste your time. \
            Nobody can recover your files without our decryption service.\r
            \r
            ## Can I recover my files?\r
            \r
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
            tPfP8wWCB9uygyfP4hUPi/1eC6vOoqYP65b1fkiyqQTg8l\r
            LyG157F2YbKj5jM5qUaJYBIHuNnETR+SLe9/rKJJHzzIIi\r
            e+wAEQcV9yJaMM85+nxGl61MHCkaLxDWkAy5p3gWqrv747\r
            dLl330zR2Y9iKqsXKq57+lMeZ0ZnhJU3b17HdYjtxxkIaF\r
            wUvsvQrfTvGpgTYoyFo6BOTCH7yXGyC/8btR/Y35WJ+Jx9\r
            8q81eyamrStzBlOPD60u5dBLrhZXnc8IAljW3knqEkAcB2\r
            nQQ092Gfn6d14ofoRo3bTq/ehF2zJiKmJWHOAi9FxRtz7N\r
            IN5Nk4byGyVHRHGfTg6HLDqaKjGNtWdJnEWVxRoaguFsfc\r
            AiZNmRENYBPOw3vtC6VJBYRBgo2P03AN4yB36GPc/sqHMq\r
            GscnL47UO20Pge6w8uRzmykzDSmSqKB4tUk2V/2XhlpMZi\r
            qQDBjhh5PDb6v9h21hantrmjixJ5Aax2ETi1jTEZKdn2N8\r
            02YiL9Uroa4f8ui34bQHuXinTFURR/+I8F+xR/F6YPubQV\r
            Q/SEvevMTcc6iIJ9eRZO5FKgdds4iaWE1f6fOhkBOgEZuc\r
            D2SeNPyigXro4sL7dw0T8WTdynb54unaJWq2J9Qw3I+rHd\r
            SIsQ0uv5dUcvfqrNjl054MxJxIHeZTuAQ3Tn97M=
        "},
        position: (CONTENT_H_START, 40),
        size: (MAX_CONTENT_WIDTH, 480),
        flags: "VSCROLL|VISIBLE",
        readonly: true,
    )]
    info_box: nwg::TextBox,

    #[nwg_control(
        text: "OWIK8IzExLK6P4jUgC2nL8I4zAXcaqLZfuLTxi52OmWhSjWdbCgeomPP2lNQTCvOOlWf",
        position: (CONTENT_H_START, 530),
        size: (MAX_CONTENT_WIDTH, 25),
    )]
    decryptor_key_input: nwg::TextInput,

    #[nwg_control(text: "Decrypt", position: (CONTENT_H_START, 560))]
    #[nwg_events(OnButtonClick: [Decryptor::say_hello])]
    decrypt_btn: nwg::Button,
}

impl Decryptor {
    fn say_hello(&self) {
        nwg::simple_message("Hello", &format!("Hello, {}!", self.decryptor_key_input.text()));
    }
}


pub fn start_decryptor_gui() -> Result<()> {
    nwg::init().with_context(|| "Failed to init Native Windows GUI")?;

    if let Err(e) = Font::set_global_family("Segoe UI") {
        eprintln!("Failed to set the global font: {e}");
    }

    let _app = Decryptor::build_ui(Default::default())
        .with_context(|| "Failed to build UI")?;

    nwg::dispatch_thread_events();

    Ok(())
}
