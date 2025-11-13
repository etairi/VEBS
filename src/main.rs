use blindves::sps::{
    SPSKeyPair,
    SPSAdjKey,
    SPSReceiverKey,
    TAG_LENGTH
};
use rand::{
    RngCore,
    rngs::OsRng
};
use std::time::Instant;
use std::mem;
use std::fs::File;
use csv::Writer;

const ITERATIONS: usize = 100;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = Writer::from_writer(File::create("TimeAndSize.csv")?);

    let spskp = SPSKeyPair::new(2);
    let sps_pk = spskp.public();
    let sps_a_kp = SPSAdjKey::new();
    let rcv_kp = SPSReceiverKey::new();

    let mut rng = OsRng;
    let mut tag = [0u8; TAG_LENGTH];
    rng.fill_bytes(&mut tag);

    // Write CSV header
    wtr.write_record(&["Scheme", "Sign", "Verify", "Resolve", "SignSize"])?;

    for _i in 1..ITERATIONS {
        // Sign
        let start_venibs_sign = Instant::now();
        let (venibs, nonce) = spskp.venibs_sign(&rcv_kp.pk, &sps_a_kp.pk, &tag);
        let dur1 = start_venibs_sign.elapsed().as_millis();
        let size = mem::size_of_val(&venibs);

        // Verify
        let start_venibs_verify = Instant::now();
        sps_pk.venibs_verify(&rcv_kp.pk, &sps_a_kp.pk, &nonce, &tag, &venibs);
        let dur2 = start_venibs_verify.elapsed().as_millis();

        // Resolve
        let start_venibs_resolve = Instant::now();
        let (sps_sig, mu) = rcv_kp.venibs_resolve_obtain(&sps_a_kp.sk, &sps_pk, &venibs, &nonce, &tag);
        let dur3: u128 =  start_venibs_resolve.elapsed().as_millis();

        sps_pk.nibs_verify(&mu, &tag, &sps_sig);

        // Write a row to the CSV
        wtr.write_record(&[
            "VENIBS",
            &dur1.to_string(),
            &dur2.to_string(),
            &dur3.to_string(),
            &size.to_string(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}