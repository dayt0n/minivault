use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

pub fn decrypt_bench(c: &mut Criterion) {
    let username = String::from("admin");
    let password = String::from("password");
    let mut vault =
        minivault::vault::Vault::new_with_password(username.clone(), password.clone()).unwrap();
    vault.unlock(username, password).unwrap();

    let (data, nonce) = vault
        .encrypt_raw(&String::from("minivault benchmark").into_bytes())
        .unwrap();

    c.bench_function("minivault decrypt", |b| {
        b.iter(|| vault.decrypt_raw(black_box(data.clone()), black_box(&nonce)));
    });
}

pub fn encrypt_bench(c: &mut Criterion) {
    let username = String::from("admin");
    let password = String::from("password");
    let mut vault =
        minivault::vault::Vault::new_with_password(username.clone(), password.clone()).unwrap();
    vault.unlock(username, password).unwrap();

    let encrypt_data = String::from("minivault benchmark").into_bytes();

    c.bench_function("minivault encrypt", |b| {
        b.iter(|| vault.encrypt_raw(black_box(&encrypt_data)));
    });
}

criterion_group!(benches, encrypt_bench, decrypt_bench);
criterion_main!(benches);
