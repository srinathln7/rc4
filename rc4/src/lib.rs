// Conditional attribute. It applies to the whole crate and informs the compiler that, unless doing a test build, 
// our library makes no assumptions about the system it's going to run on.
// no_std roughly translates to "don't depend on a standard library or runtime support being available". 
// Although this restricts us to a set of core Rust features, it makes our code portable for embedded use cases: firmware, bootloaders, kernels, etc. 
#![cfg_attr(not(test), no_std)]


// An unconditional attribute. It again applies to the entire crate, telling the compiler to ensure the library has no unsafe code blocks. 
//This allows our code to maximize Rust's memory safety guarantees, even if we refactor it or add new features later.
#![forbid(unsafe_code)]

// `derive` macro only applies to this structure, telling the compiler how to pretty print its contents to a console
#[derive(Debug)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8, 
}


impl Rc4 {
    
    // Init a new Rc4 stream cipher instance
    fn new(key :&[u8]) -> Self {
         
         // Verify valid key length (40 to 2048 bits)
         assert!(5 <= key.len() && key.len() <= 256);

         // Init our struct with default vals
         let mut rc4 = Rc4 {
            s: [0; 256],
            i: 0,
            j: 0, 
         }; 

         // Cipher state identity permutation
         for (i,b) in rc4.s.iter_mut().enumerate() {
            // s[i] = i 
            *b = i as u8; 
         }   

         // Process for 256 iterations, get starting cipher state permutation
         let mut j:u8 = 0; 
         for i in 0..256 {
            
            // j = (j + s[i] + key[i % key_len]) % 256
            
            // Wrap around is used here rather than std `+` operator to emulate modular arithmetic accounting for integer overflow  
            j = j.wrapping_add(rc4.s[i]).wrapping_add(key[i % key.len()]);

            // Swap values of s[i] and s[j]
            rc4.s.swap(i, j as usize); 
         }
            // Return our initialized Rc4  => Notice no semi-colon
            rc4 
           }

      // `prga_next` is our keystream generation function, it outputs a single keystream byte each time it's called. 
      // Unlike the new associated function, prga_next is a method. Methods always take a reference to self.  
      // parameter is &mut self, a mutable reference to the Rc4 structure on which it will be called. 
      // We need the `mut` keyword here again because this function makes changes to an Rc4 struct - it writes indexes i and j, 
      // and swaps bytes inside the cipher state buffer s   
    fn prga_next(&mut self) -> u8 {
        
        // i = (i+1) mod 256
        self.i = self.i.wrapping_add(1);  


        // j = (j + s[i]) mod 256
        self.j = self.j.wrapping_add(self.s[self.i as usize]);

        // Swap values of s[i] and s[j]
        self.s.swap(self.i as usize, self.j as usize); 

        // k = s[(s[i] + s[j]) mod 256]
        self.s[ (self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize] 
      }

    // Stateful, in-place en/decryption (current keystream XORed with data).
    // Use if plaintext/ciphertext is transmitted in chunks.  
    fn apply_keystream(&mut self, data: &mut [u8]) {
        for b_ptr in data {
            // c = k^ p where c => cipher_text, k => key, p => plain_text 
            *b_ptr ^= self.prga_next() 
        }
    }


    pub fn apply_keystream_static(key :&[u8], data: &mut[u8]) {
        let mut rc4 = Rc4::new(key); 
        rc4.apply_keystream(data); 
    }       
}



#[cfg(test)]
mod tests {
    use super::Rc4;

    #[test]
    fn sanity_check_static_api() {
        
        #[rustfmt::skip]
        let key:[u8; 16] = [
            0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
            0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2, 
        ];


        #[rustfmt::skip]
        let plaintext = [
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
            0x72, 0x6c, 0x64, 0x21,
        ]; // "Hello World!"

        let mut msg: [u8; 12] = plaintext.clone(); 

        println!(
            "Plaintext (initial): {}",
            String::from_utf8(msg.to_vec()).unwrap()
        );

        // Encrypt in-place
        Rc4::apply_keystream_static(&key, &mut msg); 
        assert_ne!(msg, plaintext);

        // Note how we don't print the ciphertext as a string, since it contains non-printable characters. 
        // We display the raw hexadecimal bytes instead
        println!("Ciphertext: {:x?}", msg); 

        // Decrypt in-place 
        Rc4::apply_keystream_static(&key,& mut msg); 
        assert_eq!(msg, plaintext); 


        println!(
            "Plaintext (decrypted): {}",
            String::from_utf8(msg.to_vec()).unwrap()
        );
    }


    #[test]
    fn ietf_40_bit_key_official_test_vectors(){
            let key: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 05]; 

            let mut out_buf: [u8; 4112] = [0x00; 4112]; 

        #[rustfmt::skip]
        let test_vectors: &[(usize, [u8; 16])] = &[
            (0, [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8]),
            (16, [0x69, 0x82, 0x94, 0x4f, 0x18, 0xfc, 0x82, 0xd5, 0x89, 0xc4, 0x03, 0xa4, 0x7a, 0x0d, 0x09, 0x19]),
            (240, [0x28, 0xcb, 0x11, 0x32, 0xc9, 0x6c, 0xe2, 0x86, 0x42, 0x1d, 0xca, 0xad, 0xb8, 0xb6, 0x9e, 0xae]),
            (256, [0x1c, 0xfc, 0xf6, 0x2b, 0x03, 0xed, 0xdb, 0x64, 0x1d, 0x77, 0xdf, 0xcf, 0x7f, 0x8d, 0x8c, 0x93]),
            (496, [0x42, 0xb7, 0xd0, 0xcd, 0xd9, 0x18, 0xa8, 0xa3, 0x3d, 0xd5, 0x17, 0x81, 0xc8, 0x1f, 0x40, 0x41]),
            (512, [0x64, 0x59, 0x84, 0x44, 0x32, 0xa7, 0xda, 0x92, 0x3c, 0xfb, 0x3e, 0xb4, 0x98, 0x06, 0x61, 0xf6]),
            (752, [0xec, 0x10, 0x32, 0x7b, 0xde, 0x2b, 0xee, 0xfd, 0x18, 0xf9, 0x27, 0x76, 0x80, 0x45, 0x7e, 0x22]),
            (768, [0xeb, 0x62, 0x63, 0x8d, 0x4f, 0x0b, 0xa1, 0xfe, 0x9f, 0xca, 0x20, 0xe0, 0x5b, 0xf8, 0xff, 0x2b]),
            (1008, [0x45, 0x12, 0x90, 0x48, 0xe6, 0xa0, 0xed, 0x0b, 0x56, 0xb4, 0x90, 0x33, 0x8f, 0x07, 0x8d, 0xa5]),
            (1024, [0x30, 0xab, 0xbc, 0xc7, 0xc2, 0x0b, 0x01, 0x60, 0x9f, 0x23, 0xee, 0x2d, 0x5f, 0x6b, 0xb7, 0xdf]),
            (1520, [0x32, 0x94, 0xf7, 0x44, 0xd8, 0xf9, 0x79, 0x05, 0x07, 0xe7, 0x0f, 0x62, 0xe5, 0xbb, 0xce, 0xea]),
            (1536, [0xd8, 0x72, 0x9d, 0xb4, 0x18, 0x82, 0x25, 0x9b, 0xee, 0x4f, 0x82, 0x53, 0x25, 0xf5, 0xa1, 0x30]),
            (2032, [0x1e, 0xb1, 0x4a, 0x0c, 0x13, 0xb3, 0xbf, 0x47, 0xfa, 0x2a, 0x0b, 0xa9, 0x3a, 0xd4, 0x5b, 0x8b]),
            (2048, [0xcc, 0x58, 0x2f, 0x8b, 0xa9, 0xf2, 0x65, 0xe2, 0xb1, 0xbe, 0x91, 0x12, 0xe9, 0x75, 0xd2, 0xd7]),
            (3056, [0xf2, 0xe3, 0x0f, 0x9b, 0xd1, 0x02, 0xec, 0xbf, 0x75, 0xaa, 0xad, 0xe9, 0xbc, 0x35, 0xc4, 0x3c]),
            (3072, [0xec, 0x0e, 0x11, 0xc4, 0x79, 0xdc, 0x32, 0x9d, 0xc8, 0xda, 0x79, 0x68, 0xfe, 0x96, 0x56, 0x81]),
            (4080, [0x06, 0x83, 0x26, 0xa2, 0x11, 0x84, 0x16, 0xd2, 0x1f, 0x9d, 0x04, 0xb2, 0xcd, 0x1c, 0xa0, 0x50]),
            (4096, [0xff, 0x25, 0xb5, 0x89, 0x95, 0x99, 0x67, 0x07, 0xe5, 0x1f, 0xbd, 0xf0, 0x8b, 0x34, 0xd8, 0x75]),
        ];

        Rc4::apply_keystream_static(&key, &mut out_buf);

        // Validate against official test vectors
        for (offset, expected) in test_vectors {
            assert_eq!(&out_buf[*offset..*offset+16] , expected)
        }

    }

}
