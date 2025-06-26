[crates.io](https://crates.io/crates/minivault) | [Documentation](https://docs.rs/minivault/)
# minivault

This is a miniature, stripped down, local version of [Hashicorp Vault's Encryption as a Service](https://developer.hashicorp.com/vault/tutorials/encryption-as-a-service). 

Once unlocked by a trusted user, permitted users on the system can query a UNIX socket to encrypt or decrypt data.

This allows data to be encrypted at rest as long as you pass all of your data through minivault. Unless someone goes through the socket, they can't read the data. 

If the system reboots and no one unlocks minivault, the data is not recoverable.

Since minivault uses UNIX sockets, local usage permisions can be done with `chown`/`chmod`. 

## How it works
Minivault encrypts and decrypts data sent to it through a UNIX socket using an AES-256-GCM master key. This key is stored, encrypted by an AES-256-GCM password-based key, in a "vault" file, which is really just a YAML file. Multiple users can be defined which can "unlock" the vault, loading the master key into memory. Each user has an entry in the vault file that contains their own copy of the encrypted master key, which is encrypted with their password as an Argon2-derived key. If the vault is "locked", then data cannot be encrypted or decrypted as the key is not yet loaded.

### Known TODOs / Pitfalls
- The master key is only as safe as the weakest user password.
- Master key rotation has yet to be implemented.
- Any user who has write access to the vault file can remove users. 
- Any user with write access to the vault file can add output from another vault file under a new user, lock minivault, then unlock it with their new user and any data that passes through will be encrypted with a completely different key or fail to decrypt old data, resulting in DoS.

The last two can be remediated by properly setting restrictive permissions on the vault YAML file.

### Windows support
Minivault works on both Linux and macOS systems. However, Windows support does not currently exist in the command line version of minivault as it relies on UNIX sockets.

## Setup

You will need to create a vault with at least one user in it with: 
```bash
$ minivault init -v /path/to/vault.yml
New admin username: administrator
New password: # enter password here
Confirm password: # again
Created new vault at /path/to/vault.yml
```

## Usage

To run minivault, point to your desired socket location and an existing vault:
```bash
$ minivault -s /path/to/minivault.sock run -v /path/to/vault.yml
```

You must first unlock minivault with a valid user before it can start decrypting and encrypting data:
```bash
$ minivault -s /path/to/minivault.sock unlock
Using "/path/to/minivault.sock"
Username: administrator
Password: # enter administrator password
Unlocked minivault!
```

### Encrypting data
minivault accepts base64 encoded data to encrypt. For instance, here we will encrypt the base64'd version of the string 'test' and return a vault string:
```bash
$ minivault -s /path/to/minivault.sock encrypt --data 'dGVzdA=='
Using "/path/to/minivault.sock"
encrypted: BG8JPiEqkVtClYkjDrxdsmwNXzk=:gjWwU98m1NHYUUjQ
```

You can also use an HTTP client, such as `curl`:
```bash
$ curl -s -X POST --unix-socket /path/to/minivault.sock http://minivault/encrypt -H 'Content-Type: application/json' -d '{"encrypt": {"data":"dGVzdA=="}}'
{"status":"success","msg":"uAq1cwByuyRaayaTK3AyoVsVneE=:nfwVnm9RV3h_giU_"}
```

### Decrypting data
Take the encrypted vault string you received from minivault and then pass it back with:
```bash
$ minivault decrypt --data 'BG8JPiEqkVtClYkjDrxdsmwNXzk=:gjWwU98m1NHYUUjQ'
Using "/path/to/minivault.sock"
decrypted: dGVzdA==
```

Again, you can use an HTTP client, such as `curl`, to decrypt:
```bash
$ curl -s -X POST --unix-socket /path/to/minivault.sock http://minivault/decrypt -H 'Content-Type: application/json' -d '{"decrypt": {"data":"uAq1cwByuyRaayaTK3AyoVsVneE=:nfwVnm9RV3h_giU_"}}'
{"status":"success","msg":"dGVzdA=="}%
```

### Example clients
A few example clients in other programming languages have been provided in the [example-clients/](./example-clients/) folder.

### Other functionality
You can also add users, change user passwords, and lock the vault using other included subcommands which you can see with:
```bash
$ minivault --help
```

### As a library
Minivault exposes the `vault`, `server`, and `client` crates. Pull any of them in with:
```rust
use minivault::vault;
use minivault::server;
use minivault::client;
// Or
use minivault::*;
```

See [docs.rs](https://docs.rs/minivault/latest/minivault/) for more information on using minivault as a crate in your project.

## Development
Feel free to contribute to minivault's development via PR!

### Building
For a development version, run:
```bash
$ cargo run -- [subcommands]
```

For a release version, do:
```bash
# this takes longer to compile, but has much better performance when running
$ cargo run -r -- [subcommands]
```

### Testing
Run all tests with:
```bash
$ cargo test
```

### Benchmarking
Benchmarks for encryption and decryption using [criterion](https://github.com/bheisler/criterion.rs) are provided. Run them with:
```bash
$ cargo bench
```

Below are the benchmarks for encrypt and decrypt operations from a Macbook Pro (2019) with the following specs:
- **CPU:** Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz
- **Memory:** 32 GB 2667 MHz DDR4
- **GPU:** Intel UHD Graphics 630 1536 MB

```bash
minivault encrypt  time:   [1.3020 µs 1.3140 µs 1.3271 µs]

minivault decrypt  time:   [291.95 ns 294.68 ns 297.33 ns]
```

### Profiling
A small script is provided at [profile.sh](./profile.sh), which uses [cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph) to generate a flamegraph of a running minivault instance.
```bash
$ ./profile.sh
```