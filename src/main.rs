
use aes_gcm::aead::{Aead, Payload, Nonce};
use aes_gcm::{Aes256Gcm, Key, KeyInit}; 

use hmac::{Hmac, Mac as MacTrait};  
use sha2::{Sha512, Sha256, Digest};

use generic_array::{GenericArray, typenum::U32};
use generic_array::typenum::U12; 
use hex::FromHex;  
use serde_json;  
use secp256k1::{ecdh, PublicKey, SecretKey};  

use rand;
use serde_json::json;

type HmacSha256 = Hmac<Sha256>; 

fn hex_str_to_bytes(hex: &str) -> Vec<u8> {  
    Vec::from_hex(hex).expect("Invalid hex string")  
}  

pub fn encrypt_message(
    message: &[u8],
    recipient_public_key: &PublicKey,
    ephemeral_secret_key: &SecretKey,
) -> serde_json::Value {
    // Generate shared secret
    let shared_secret = ecdh::SharedSecret::new(recipient_public_key, ephemeral_secret_key);
    let shared_secret_bytes = shared_secret.as_ref();

    let hash = Sha512::digest(shared_secret_bytes);
    let enc_key = &hash[..32];
    let mac_key = &hash[32..64];


    let mut key_array: GenericArray<u8, U32> = GenericArray::default();
    key_array.copy_from_slice(enc_key);
    let key: Key<Aes256Gcm> = key_array.into();
    let cipher = Aes256Gcm::new(&key);

    let iv: [u8; 12] = rand::random();
    let nonce = Nonce::<Aes256Gcm>::from(iv);
    let secp = secp256k1::Secp256k1::new();
    let ephem_pub_key = PublicKey::from_secret_key(&secp, ephemeral_secret_key);
    let ephem_pub_key_bytes = ephem_pub_key.serialize_uncompressed();

    // Encrypt the message
    let payload = Payload {
        msg: message,
        aad: &ephem_pub_key_bytes,
    };
    
    let ciphertext = cipher.encrypt(&nonce, payload)
        .expect("Encryption failed!");

    let mut mac_calculator = <HmacSha256 as MacTrait>::new_from_slice(mac_key)
    .expect("HMAC initialization failed");
    mac_calculator.update(&iv);
    mac_calculator.update(&ephem_pub_key_bytes);
    mac_calculator.update(&ciphertext);
    let mac = mac_calculator.finalize();

    json!({
        "iv": hex::encode(iv),
        "ephemPublicKey": hex::encode(ephem_pub_key_bytes),
        "ciphertext": hex::encode(ciphertext),
        "mac": hex::encode(mac.into_bytes())
    })
}
fn main() {  
    //Encrypted message from encrypt_message
    let encrypted_data = r#"{  
        "iv": "fc623e3e5606275ea7944274",  
        "ephemPublicKey": "0462587c0bd9390d13cfacc6fffcdcad8ce90691c4f71224fbbf6f28711930c85f62d68300dcfb0d714d47bcdcf69f7d31e4be5fc16df4376abb4e0ff5b1a6d940",  
        "ciphertext": "9a3981cd192b58ee75ba993e762f4e669eaf4007",  
        "mac": "c51d3a0a058deb4cd70ca8967a2493ac4cf1004a806b6ef2eeca83a7ec7b957d"  
    }"#;  

    let data: serde_json::Value = serde_json::from_str(encrypted_data).unwrap();  

    let iv_hex = data["iv"].as_str().unwrap();  
    let ephem_pub_key_hex = data["ephemPublicKey"].as_str().unwrap();  
    let ciphertext_hex = data["ciphertext"].as_str().unwrap();  

    let iv = hex_str_to_bytes(iv_hex);  
    let ephem_pub_key = hex_str_to_bytes(ephem_pub_key_hex);  
    let ciphertext = hex_str_to_bytes(ciphertext_hex);  

    let private_key_hex = "ea2861b1058084974c509a4d2e21e73896059c1c69f7a5c2650661cac3493725";
    let private_key_bytes = hex_str_to_bytes(private_key_hex);  
    let sk = SecretKey::from_slice(&private_key_bytes).expect("Invalid secret key!");  

    let pub_key = PublicKey::from_slice(&ephem_pub_key).expect("Invalid public key");  
    let shared_secret = ecdh::SharedSecret::new(&pub_key, &sk); 
    let shared_secret_bytes = shared_secret.as_ref(); 

    let hash = Sha512::digest(shared_secret_bytes);
  
    let enc_key = &hash[..32];
    let mac_key = &hash[32..64];
    
    let mut key_array: GenericArray<u8, U32> = GenericArray::default();
    key_array.copy_from_slice(enc_key); 
    
    let key: Key<Aes256Gcm> = key_array.into();
    let cipher = Aes256Gcm::new(&key); 

    let mut mac_calculator = <HmacSha256 as MacTrait>::new_from_slice(mac_key)
    .expect("HMAC initialization failed");

    mac_calculator.update(&iv);
    mac_calculator.update(&ephem_pub_key);
    mac_calculator.update(&ciphertext);

    let nonce_array: GenericArray<u8, U12> = GenericArray::clone_from_slice(&iv[..12]);
    let nonce = Nonce::<Aes256Gcm>::from(nonce_array);
    
    let mut full_ciphertext = hex_str_to_bytes(ciphertext_hex);
    let mac_bytes = hex_str_to_bytes(data["mac"].as_str().unwrap());
    full_ciphertext.extend_from_slice(&mac_bytes);

    let payload = Payload {
        msg: ciphertext.as_ref(),
        aad: &ephem_pub_key  
    };

    let computed_mac = mac_calculator.finalize();
    let expected_mac = hex_str_to_bytes(data["mac"].as_str().unwrap());
    
    println!("Expected MAC: {}", hex::encode(&expected_mac));
    println!("Computed MAC: {}", hex::encode(computed_mac.clone().into_bytes()));
    

    let msg_len = payload.msg.len();
    let aad_len = payload.aad.len();
    let msg_hex = hex::encode(payload.msg);
    let aad_hex = hex::encode(payload.aad);
    
    let plaintext = match cipher.decrypt(&nonce, payload) {
        Ok(plaintext) => {
            println!("Decryption successful!");
            plaintext
        },
        Err(e) => {
            println!("=== Detailed Error Analysis ===");
            println!("Error details: {}", e);
            println!("Debug view: {:?}", e);
            
            println!("\nParameter Values (hex):");
            println!("Nonce: {}", hex::encode(&nonce));
            println!("Ciphertext: {}", msg_hex);
            println!("AAD: {}", aad_hex);
            println!("Key: {}", hex::encode(enc_key));
            
            println!("\nParameter Lengths:");
            println!("Nonce: {} bytes", nonce.len());
            println!("Ciphertext: {} bytes", msg_len);
            println!("AAD: {} bytes", aad_len);
            println!("Key: {} bytes", enc_key.len());
            
            Vec::new()
        }
    };
    
    if plaintext.is_empty() {
    println!("Decryption produced no output - check debug information above");
    } else {
    println!("Decrypted message length: {}", plaintext.len());
    }

    let decrypted_message = String::from_utf8(plaintext).expect("Failed to convert plaintext to string"); 
 
    println!("Shared Secret Bytes: {:?}", shared_secret_bytes); 
    println!("Key Array: {:?}", key_array.as_slice()); 

    println!("Enc Key: {:?}", enc_key);
    println!("Nonce: {:?}", nonce); 
    println!("Ciphertext : {:?}", ciphertext);
    println!("Decrypted message: {}", decrypted_message);  
    let mut rng = rand::thread_rng();
    let ephemeral_secret_key = SecretKey::new(&mut rng);
    
    // Convert message string to bytes
    let message = "okay".as_bytes();
    
    // Convert hex public key string to PublicKey object
    let pubkey_bytes = hex::decode("04ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4").unwrap();
    let recipient_public_key = PublicKey::from_slice(&pubkey_bytes).unwrap();
    
    let encrypted = encrypt_message(
        message,
        &recipient_public_key,
        &ephemeral_secret_key
    );
    println!("Encrypted message: {:?}", encrypted);

    println!("Code Works!");   
}



