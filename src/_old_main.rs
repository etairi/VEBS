use blindves::bls::{
    BLSKeyPair,
    BLSAdjKey,
    BLSUserState
};
use blindves::schnorr::SchnorrPair;
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

    // Key generation
    let blskp = BLSKeyPair::new();
    let bls_pk = blskp.public();
    let a_kp = BLSAdjKey::new();

    let schnorr_kp = SchnorrPair::new();
    let y_kp = SchnorrPair::new();

    let m = "TestMessage";

    let spskp = SPSKeyPair::new(2);
    let sps_pk = spskp.public();
    let sps_a_kp = SPSAdjKey::new();
    let rcv_kp = SPSReceiverKey::new();

    let mut rng = OsRng;
    let mut tag = [0u8; TAG_LENGTH];
    rng.fill_bytes(&mut tag);

    // Write CSV header
    wtr.write_record(&["Scheme", "Setup", "Buy", "Get", "ComCost"])?;

    for _i in 1..ITERATIONS {
        // Start with VEBS
        let (user_state_bls, rho_u_bls) = BLSUserState::user(&bls_pk, &m);

        // Algorithm Setup
        let start_vebsign = Instant::now();

        let vebs = blskp.vebsign(&a_kp.pk, &rho_u_bls);

        let dur1 = start_vebsign.elapsed().as_millis() ;
        let mut size1= mem::size_of_val(&vebs);

        // Algorithm buy
        let start_vebs_verify = Instant::now();
        bls_pk.vebs_verify(&a_kp.pk, &rho_u_bls, &vebs);
        let presign_bls = schnorr_kp.pre_sign(&m, &y_kp.pk);

        let dur2 = start_vebs_verify.elapsed().as_millis();
        size1 = size1 + mem::size_of_val(&presign_bls);

        let signature_b = presign_bls.adapt(&y_kp.sk);

        // Algorithm get
        let _y = presign_bls.extract(&signature_b);
        let start_vebs_resolve = Instant::now();

        let rho_s_bls = a_kp.vebs_resolve(&rho_u_bls, &bls_pk, &vebs);
        let dur3 = start_vebs_resolve.elapsed().as_millis();

        let sigma_vebs = user_state_bls.derive(&rho_s_bls);

        bls_pk.verify( &m, &sigma_vebs);
 
        // Write a row to the CSV
        wtr.write_record(&[
            "VEBS",
            &dur1.to_string(),
            &dur2.to_string(),
            &dur3.to_string(),
            &size1.to_string(),
        ])?;

        // Now with VENIBS-TRICKY
        // Algorithm Setup
        let start_venibs_sign_tricky = Instant::now();

        let (venibs_tricky, nonce_tricky) = spskp.venibs_sign_tricky(&rcv_kp.pk, &sps_a_kp.pk, &tag);
        
        let dur4 = start_venibs_sign_tricky.elapsed().as_millis();
        let mut size2 = mem::size_of_val(&venibs_tricky);

        // Algorithm Buy
        let start_venibs_verify_tricky = Instant::now();
        sps_pk.venibs_verify_tricky(&rcv_kp.pk, &sps_a_kp.pk, &nonce_tricky, &tag, &venibs_tricky);

        let presign_sps = schnorr_kp.pre_sign(&m, &y_kp.pk);

        let dur5 = start_venibs_verify_tricky.elapsed().as_millis();
        size2 = size2 + mem::size_of_val(&presign_sps);

        let signature_s = presign_sps.adapt(&y_kp.sk);

        // Algorithm Get
        let _y = presign_sps.extract(&signature_s);
        let start_venibs_resolve_tricky = Instant::now();

        let (sps_sig, mu) = rcv_kp.venibs_resolve_obtain_tricky(&sps_a_kp.sk, &sps_pk, &venibs_tricky, &nonce_tricky, &tag);
        let dur6 =  start_venibs_resolve_tricky.elapsed().as_millis();

        sps_pk.nibs_verify( &mu, &tag, &sps_sig);

        // Write a row to the CSV
        wtr.write_record(&[
            "VENIBS-TRICKY",
            &dur4.to_string(),
            &dur5.to_string(),
            &dur6.to_string(),
            &size2.to_string(),
        ])?;

        // Now with plain VENIBS
        // Algorithm Setup
        let start_venibs_sign = Instant::now();

        let (venibs, nonce) = spskp.venibs_sign(&rcv_kp.pk, &sps_a_kp.pk, &tag);
        
        let dur7 = start_venibs_sign.elapsed().as_millis();
        let mut size3 = mem::size_of_val(&venibs);

        // Algorithm Buy
        let start_venibs_verify = Instant::now();
        sps_pk.venibs_verify(&rcv_kp.pk, &sps_a_kp.pk, &nonce, &tag, &venibs);

        let presign_sps = schnorr_kp.pre_sign(&m, &y_kp.pk);

        let dur8 = start_venibs_verify.elapsed().as_millis();
        size3 = size3 + mem::size_of_val(&presign_sps);

        let signature_s = presign_sps.adapt(&y_kp.sk);

        // Algorithm Get
        let _y = presign_sps.extract(&signature_s);
        let start_venibs_resolve = Instant::now();

        let (sps_sig, mu) = rcv_kp.venibs_resolve_obtain(&sps_a_kp.sk, &sps_pk, &venibs, &nonce, &tag);
        let dur9 =  start_venibs_resolve.elapsed().as_millis();

        sps_pk.nibs_verify(&mu, &tag, &sps_sig);

        // Write a row to the CSV
        wtr.write_record(&[
            "VENIBS",
            &dur7.to_string(),
            &dur8.to_string(),
            &dur9.to_string(),
            &size3.to_string(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}