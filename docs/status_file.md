# Status file

## Location
`$encryption_root/.bigrat_status`

Also see here: [Encrypted files location](encrypted_files.md#location)

## Contents

| Content                              | Length (bytes)                         |
|--------------------------------------|----------------------------------------|
| bigrat.png                           | length of bigrat.png                   |
| encrypted key                        | 256                                    |
| encrypted nonce                      | 256                                    |
| encrypted status verification string | 26 (`STATUS_VERIFY_ENCRYPTED_STR_LEN`) |
| encryption status                    | until the end of the file              |

### Encryption status verification string
Encrypted string `"bigratware"` (saved in `STATUS_VERIFY_STR`) used for verification of the user-provided decrypted key-nonce pair

### Encryption status format
It's saved as a chain of strings in the format `BIGRATWARE_STATUS=started;`, where `started` is the encryption status itself, which can be of value either `started` of `finished`
