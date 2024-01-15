use std::io;
use std::path::PathBuf;
use rand::Rng;

/// Returns ideal_path if it doesn't exist on the system,
/// or else generates a nonexistent path based on it
/// by adding a random u32 number as a prefix
///
/// If `always_random` is true, it always generates a random prefix
pub fn gen_new_path(ideal_path: PathBuf, always_random: bool) -> io::Result<PathBuf> {
    match ideal_path.try_exists() {
        Ok(exists) => {
            if !exists && !always_random { return Ok(ideal_path) }

            let mut rng = rand::thread_rng();
            loop {
                let new_path = ideal_path.with_file_name(
                    rng.gen::<u32>().to_string() + "-" +
                    ideal_path.file_name().unwrap().to_str().unwrap()
                );
                match new_path.try_exists() {
                    Ok(exists) => if !exists { return Ok(new_path) }
                    Err(e) => return Err(e)
                };
            };
        }
        Err(e) => Err(e)
    }
}
