use secp256kfun::{
    g, G,
    s, Scalar as ChainScalar,
    Point
};
use sha2::{digest::Digest, Sha256};
use rand::rngs::OsRng;

// The construction is from https://eprint.iacr.org/2020/476.pdf
pub struct SchnorrPair {
    pub sk: ChainScalar,
    pub pk: Point,
}

pub struct SchnorrSig {
    s: ChainScalar,
    r: ChainScalar,
}

pub struct SchnorrPreSig {
    pub s: ChainScalar,
    pub r: ChainScalar,
}

impl SchnorrPair {
    pub fn new() -> Self {
        let sk =  sample_rand_chain_scalar();
        let pk = g!(sk * G).normalize();

        Self {
            sk,
            pk,
        }
    }

    pub fn sign(&self, m: &str) -> SchnorrSig {
        let k =  sample_rand_chain_scalar();
        let big_k = g!(k * G).normalize();

        let r = schnorr_hash(&self.pk, big_k, m);    
        let mut s = s!(r * self.sk);
        s = s!(k + s).expect_nonzero("unlikely that k, which is random and s add up to zero");

        SchnorrSig{
            s,
            r
        }
    }

    pub fn pre_sign(&self, m: &str, y_pub: &Point) -> SchnorrPreSig {
        let k =  sample_rand_chain_scalar();
        let mut big_k = g!(k * G).normalize();
        big_k = g!(y_pub + big_k).normalize().expect_nonzero(" ");
    
        let r = schnorr_hash(&self.pk, big_k, m);    
        let mut s = s!(r * self.sk);
        s = s!(k + s).expect_nonzero(" ");
    
        SchnorrPreSig{
            s,
            r
        }
    }

}

impl SchnorrSig {
    pub fn verify(&self, pk: &Point, m: &str)-> () {
        let mut rand = g!(self.r * pk).normalize();
        let gs = g!(self.s*G).normalize();
        rand = g!(gs-rand).normalize().expect_nonzero(" ");

        let got = schnorr_hash(pk, rand, m);
        assert!(got == self.r, "Invalid Schnorr Signature");
    }
}

impl SchnorrPreSig {
    pub fn pre_verify(&self, pk: &Point, m: &str, y_pub: &Point) -> () {
        let mut rand = g!(self.r * pk).normalize();
        let gs = g!(self.s*G).normalize();
        rand = g!(gs - rand).normalize().expect_nonzero(" ");
        rand = g!(rand+y_pub).normalize().expect_nonzero(" ");

        let got = schnorr_hash(pk, rand, m);
        assert!(got == self.r, "Invalid Schnorr PreSignature");
    }

    pub fn adapt(&self, y: &ChainScalar) -> SchnorrSig{
        let s = s!(self.s + y).expect_nonzero(" ");
        let r = &self.r;
    
        SchnorrSig{
            s,
            r: r.clone()
        }
    }

    pub fn extract(&self, s: &SchnorrSig) -> ChainScalar{
        let y = s!(self.s - s.s).expect_nonzero(" ");

        y
    }
}

pub fn sample_rand_chain_scalar() -> ChainScalar{
    let scalar =  ChainScalar::random(&mut OsRng);

    scalar
}

pub fn schnorr_hash(pk: &Point, rand:Point, m: &str) -> ChainScalar {
    // Step 1. Serialize inputs
    let mut serialized_data = Vec::new();

    // Serialize pk
    let pk_bytes = pk.to_bytes();
    serialized_data.extend(pk_bytes);

    // Serialize rand
    let rand_bytes = rand.to_bytes();
    serialized_data.extend(rand_bytes);

    // Serialize message
    let m_bytes = m.bytes();
    serialized_data.extend(m_bytes);

    // Step 2: Hash the concatenated serialized data
    let mut hasher = Sha256::new();
    hasher.update(&serialized_data);
    let hash_result = hasher.finalize(); 

    // Step 3: transform from bytes to scalar
    let r = ChainScalar::from_bytes_mod_order(hash_result.try_into().unwrap()).expect_nonzero("the output of the hash cannot be known in advance");

    r
}
