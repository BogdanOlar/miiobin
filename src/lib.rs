//! Implementation of the local Mi Home binary protocol.
//!
//! This protocol is used by the MiHome smartphone app to communicate with the robot on
//! a local network (including for provisioning the robot)
//!
//! The `MiPacket` is used to encapsulate encrypted messages (`MiMessage`)
//!
//!

use std::fmt;
use std::error::Error as StdError;
use crypto::md5::{Md5};
use crypto::digest::Digest;
use openssl::symm::{Cipher, Mode, Crypter};

/// MiIO discover packet
pub const MI_DISCOVER_PACKET: [u8; 32] = [0x21, 0x31, 0x00, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// Minimum size of a MiIO packet
const RAW_HEADER_SIZE: usize = 32;

/// First two bytes of a MiIO packet
const MAGIC_NUMBER: u16 = 0x2131;

/// Structure used to represent a MiIO packet
#[derive(Debug)]
pub struct MiPacket {
    pub reserved: u32,
    pub device_id: u32,
    pub stamp: u32,
    pub md5: [u8; 16],
    pub payload: Vec<u8>
}

impl MiPacket {
    /// Create an empty `MiPacket` with default values
    ///
    /// # Arguments
    /// `device_id` - The device ID
    /// `stamp` - The message stamp
    ///
    pub fn new(device_id: u32, stamp: u32) -> MiPacket {
        MiPacket {
            reserved: 0,
            device_id,
            stamp,
            md5: [0u8; 16],
            payload: Vec::new()
        }
    }

    /// Create a new `MiPacket` from a raw buffer.
    ///
    /// # Remarks
    /// This function does not check the md5 of the packet. (In order to be able to parse
    /// discovery responses, which always contain 0xff bytes in the md5 field)
    ///
    /// # Arguments
    /// `src` - Buffer containing the raw packet
    ///
    pub fn parse(src: &[u8]) -> Result<MiPacket, Error> {
        if src.len() < RAW_HEADER_SIZE {
            return Err(Error::PacketTooSmall(src.len()));
        }

        let magic_number: u16 = ((src[0] as u16) << 8) | ((src[1] as u16) << 0);
        let length: u16 = ((src[2] as u16) << 8) | ((src[3] as u16) << 0);

        if magic_number != MAGIC_NUMBER {
            return Err(Error::MagicNumber(magic_number));
        }
        else if src.len() != (length as usize) {
            return Err(Error::BufferLength((src.len(), length as usize)));
        }

        let reserved: u32 =
            ((src[ 4] as u32) << 24) |
            ((src[ 5] as u32) << 16) |
            ((src[ 6] as u32) <<  8) |
            ((src[ 7] as u32) <<  0);

        let device_id: u32 =
            ((src[ 8] as u32) << 24) |
            ((src[ 9] as u32) << 16) |
            ((src[10] as u32) <<  8) |
            ((src[11] as u32) <<  0);

        let stamp: u32 =
            ((src[12] as u32) << 24) |
            ((src[13] as u32) << 16) |
            ((src[14] as u32) <<  8) |
            ((src[15] as u32) <<  0);

        let mut payload: Vec<u8> = Vec::new();

        if src.len() > RAW_HEADER_SIZE {
            payload.extend_from_slice(&src[32..]);
        }

        // return packet
        Ok(MiPacket {
            reserved,
            device_id,
            stamp,
            md5: [src[16], src[17], src[18], src[19], src[20], src[21], src[22], src[23], src[24], src[25], src[26],
                src[27], src[28], src[29], src[30], src[31]],    // ugh...
            payload,
        })
    }

    /// Parse the given buffer, check the MD5, decrypt and return decrypted packet
    ///
    /// # Arguments
    /// `src` - Buffer containing the raw packet
    /// `token` - Token is used to initialize the md5 field in the `src` and decrypt the payload
    ///
    pub fn parse_decrypt(src: &[u8], token: &[u8; 16]) -> Result<MiPacket, Error> {
        let mut packet = MiPacket::parse(src)?;

        // check md5
        let mut hasher: Md5 = Md5::new();
        hasher.input(&src[..16]);
        hasher.input(&token[..]);

        if packet.payload.len() > 0 {
            hasher.input(&src[RAW_HEADER_SIZE..]);
        }

        hasher.result(&mut packet.md5[..]);

        if &src[16..RAW_HEADER_SIZE] != packet.md5 {
            return Err(Error::Md5Mismatch);
        }

        // decrypt payload
        if !packet.decrypt(token) {
            return Err(Error::Decrypt);
        }

        Ok(packet)
    }


    /// Pack the structure into a given `dest` buffer.
    ///
    /// # Remarks
    /// This function WILL calculate the md5 over the entire length of the packet.
    ///
    /// # Arguments
    /// `dest` - Destination buffer. Needs to be at least as large as the value returned by `packed_size`
    /// `token` - Token is used to initialize the md5 field in the output
    ///
    /// # Returns
    /// `Result` where the `Ok` variant contains the number of bytes written to the `dest` buffer.
    ///
    pub fn pack(&mut self, dest: &mut [u8], token: &[u8; 16]) -> Result<usize, Error> {
        let packed_size: usize = self.packed_size();

        if dest.len() < packed_size {
            return Err(Error::BufferLength((packed_size, dest.len())));
        }

        // magic number
        dest[0] = (MAGIC_NUMBER >> 8) as u8;
        dest[1] = (MAGIC_NUMBER >> 0) as u8;

        // length
        let length: u16 = packed_size as u16;
        dest[2] = (length >> 8) as u8;
        dest[3] = (length >> 0) as u8;

        // reserved
        dest[4] = (self.reserved >> 24) as u8;
        dest[5] = (self.reserved >> 16) as u8;
        dest[6] = (self.reserved >> 8) as u8;
        dest[7] = (self.reserved >> 0) as u8;

        // device ID
        dest[8] = (self.device_id >> 24) as u8;
        dest[9] = (self.device_id >> 16) as u8;
        dest[10] = (self.device_id >> 8) as u8;
        dest[11] = (self.device_id >> 0) as u8;

        // stamp
        dest[12] = (self.stamp >> 24) as u8;
        dest[13] = (self.stamp >> 16) as u8;
        dest[14] = (self.stamp >> 8) as u8;
        dest[15] = (self.stamp >> 0) as u8;

        // copy payload
        if self.payload.len() > 0 {
            dest[RAW_HEADER_SIZE..packed_size].copy_from_slice(self.payload.as_slice());
        }

        // md5 is initialized to the token value
        dest[16..RAW_HEADER_SIZE].clone_from_slice(token);

        // calculate md5
        let mut hasher: Md5 = Md5::new();
        hasher.input(&dest[0..packed_size]);

        // save calculated md5
        hasher.result(&mut self.md5);

        // overwrite the token in the buffer with the calculated md5
        dest[16..RAW_HEADER_SIZE].copy_from_slice(&self.md5);

        // return the size of the packet
        Ok(packed_size)
    }

    /// Encrypt the packet, calculate the MD5, and serialize to the given `dest` buffer
    ///
    /// # Arguments
    /// `dest` - Destination buffer. Needs to be at least as large as the value returned by `packed_encrypted_size`
    /// `token` - Token is used to encrypt the payload and initialize the md5 field in the `dest` buffer
    ///
    pub fn pack_encrypt(&mut self, dest: &mut [u8], token: &[u8; 16]) -> Result<usize, Error> {
        // decrypt payload
        if !self.encrypt(token) {
            return Err(Error::Encrypt);
        }
        self.pack(dest, token)
    }

    /// Decrypt the payload of the packet, return `false` if decryption fails.
    ///
    /// # Arguments
    /// `token` - 16 byte token used to decrypt the payload
    ///
    pub fn decrypt(&mut self, token: &[u8; 16]) -> bool{
        if self.payload.len() == 0 {
            return false;
        }

        // Initialize key
        let mut hasher: Md5 = Md5::new();
        hasher.input(&token[..]);
        let mut key: [u8; 16] = [0u8; 16];
        hasher.result(&mut key);

        // Initialize IV
        let mut hasher: Md5 = Md5::new();
        hasher.input(&key[..]);
        hasher.input(&token[..]);
        let mut iv: [u8; 16] = [0u8; 16];
        hasher.result(&mut iv);

        // Initialize cipher
        match Crypter::new(
            Cipher::aes_128_cbc(),
            Mode::Decrypt,
            &key,
            Some(&iv)) {
            Ok(mut _decrypter) => {
                // Decrypt payload into a temporary vector
                let mut plaintext: Vec<u8> = vec![0u8; self.payload.len() + Cipher::aes_128_cbc().block_size()];
                match _decrypter.update(self.payload.as_slice(), plaintext.as_mut_slice()) {
                    Ok(count) => {
                        match _decrypter.finalize(&mut plaintext[count..]) {
                            Ok(count_finalize) => {
                                plaintext.truncate(count + count_finalize);
                                // Save decrypted payload
                                self.payload = plaintext;
                                return true;
                            }
                            Err(_) => {}
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }

        // decryption failed
        false
    }

    /// Encrypt the payload of the packet, return `false` if encryption fails
    ///
    /// # Remarks
    /// The size of the encrypted payload may end up being larger than the size of the plaintext payload.
    ///
    /// # Arguments
    /// `token` - 16 byte token used to encrypt the payload
    ///
    pub fn encrypt(&mut self, token: &[u8; 16]) -> bool{
        if self.payload.len() == 0 {
            return true;
        }

        // Initialize key
        let mut hasher: Md5 = Md5::new();
        hasher.input(&token[..]);
        let mut key: [u8; 16] = [0u8; 16];
        hasher.result(&mut key);

        // Initialize IV
        let mut hasher: Md5 = Md5::new();
        hasher.input(&key[..]);
        hasher.input(&token[..]);
        let mut iv: [u8; 16] = [0u8; 16];
        hasher.result(&mut iv);

        // Initialize cipher
        // Encrypt payload into a temporary vector, assign it to `self.payload` if successful
        match Crypter::new(
            Cipher::aes_128_cbc(),
            Mode::Encrypt,
            &key,
            Some(&iv)) {
            Ok(mut _encrypter) => {
                let mut cyphertext: Vec<u8> = vec![0u8; self.payload.len() + Cipher::aes_128_cbc().block_size()];
                match _encrypter.update(self.payload.as_slice(), cyphertext.as_mut_slice()) {
                    Ok(count) => {
                        match _encrypter.finalize(&mut cyphertext[count..]) {
                            Ok(count_finalize) => {
                                cyphertext.truncate(count + count_finalize);
                                self.payload = cyphertext;
                                return true;
                            }
                            Err(_) => {}
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }

        // encryption failed
        false
    }

    /// Return the size of the packet when packed into an output buffer.
    ///
    pub fn packed_size(&self) -> usize {
        RAW_HEADER_SIZE + self.payload.len()
    }

    /// Return the size of the unencrypted packet when encrypted and packed into an output buffer.
    ///
    pub fn packed_encrypted_size(&self) -> usize {
        RAW_HEADER_SIZE + self.payload.len() + Cipher::aes_128_cbc().block_size()
    }
}

/// Error types returned by functions in this module
#[derive(Debug)]
pub enum Error {
    PacketTooSmall(usize),
    MagicNumber(u16),
    BufferLength((usize, usize)),
    Encrypt,
    Decrypt,
    Md5Mismatch,
}

/// `Display` trait implementation for `packet::Error`
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::PacketTooSmall(packet_length) => f.write_fmt(
                format_args!("Packet length < {} bytes: {}", RAW_HEADER_SIZE, packet_length)),
            Error::MagicNumber(magic_number) => f.write_fmt(
                format_args!("Wrong magic number: {}", magic_number)),
            Error::BufferLength((expected, found)) => f.write_fmt(
                format_args!("Expected length: {}, found: {}", expected, found)),
            Error::Encrypt => f.write_str("Encryption failed"),
            Error::Decrypt => f.write_str("Decryption failed"),
            Error::Md5Mismatch => f.write_str("Calculated MD5 does not match packet MD5 field"),
        }
    }
}

/// `Error` trait implementation for `packet::Error`
impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::PacketTooSmall(_packet_length) => "Packet length is smaller than 32 bytes.",
            Error::MagicNumber(_magic_number) => "Wrong magic number",
            Error::BufferLength((_expected, _found)) => "Packet length does not match expected length",
            Error::Encrypt => "Encryption failed",
            Error::Decrypt => "Decryption failed",
            Error::Md5Mismatch => "Calculated MD5 does not match packet MD5 field",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DEVICE_ID: u32 = 123456789;
    const TEST_STAMP: u32 = 33333;
    const TEST_TOKEN: [u8; 16] = [73, 115, 79, 119, 84, 115, 100, 100, 108, 72, 52, 115, 107, 106, 107, 80];

    /// Example of plaintext payload sent from the MiHome app when provisioning a Xiaomi Roborock S5 vacuum cleaner
    /// The app passes the router credentials to the robot in a packet encrypted with the token obtained from the
    /// discovery response packet
    const TEST_PAYLOAD: &[u8; 247] = b"{\"id\":1234567890,\"method\":\"miIO.config_router\",\"params\":{\"ssid\":\
                                      \"MyRouterSSID\",\"passwd\":\"MyRouterPassword\",\"uid\":9876543210,\"bind_key\":\
                                      \"\",\"config_type\":\"app\",\"country_domain\":\"de\",\"wifi_config\":{\"cc\":\
                                      \"DE\"},\"gmt_offset\":3600,\"tz\":\"Europe\\/Prague\"}}";

    /// Packet containing the `TEST_PAYLOAD` in plaintext
    const TEST_PACKET_PLAINTEXT: [u8; 279] = [33, 49, 1, 23, 0, 0, 0, 0, 7, 91, 205, 21, 0, 0, 130, 53, 76, 166, 235,
        231, 28, 3, 217, 204, 19, 207, 1, 243, 26, 179, 220, 215, 123, 34, 105, 100, 34, 58, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 48, 44, 34, 109, 101, 116, 104, 111, 100, 34, 58, 34, 109, 105, 73, 79, 46, 99, 111, 110, 102, 105, 103,
        95, 114, 111, 117, 116, 101, 114, 34, 44, 34, 112, 97, 114, 97, 109, 115, 34, 58, 123, 34, 115, 115, 105, 100,
        34, 58, 34, 77, 121, 82, 111, 117, 116, 101, 114, 83, 83, 73, 68, 34, 44, 34, 112, 97, 115, 115, 119, 100, 34,
        58, 34, 77, 121, 82, 111, 117, 116, 101, 114, 80, 97, 115, 115, 119, 111, 114, 100, 34, 44, 34, 117, 105, 100,
        34, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 44, 34, 98, 105, 110, 100, 95, 107, 101, 121, 34, 58, 34, 34,
        44, 34, 99, 111, 110, 102, 105, 103, 95, 116, 121, 112, 101, 34, 58, 34, 97, 112, 112, 34, 44, 34, 99, 111, 117,
        110, 116, 114, 121, 95, 100, 111, 109, 97, 105, 110, 34, 58, 34, 100, 101, 34, 44, 34, 119, 105, 102, 105, 95,
        99, 111, 110, 102, 105, 103, 34, 58, 123, 34, 99, 99, 34, 58, 34, 68, 69, 34, 125, 44, 34, 103, 109, 116, 95,
        111, 102, 102, 115, 101, 116, 34, 58, 51, 54, 48, 48, 44, 34, 116, 122, 34, 58, 34, 69, 117, 114, 111, 112, 101,
        92, 47, 80, 114, 97, 103, 117, 101, 34, 125, 125];

    /// Packet containing the `TEST_PAYLOAD` encrypted with the `TEST_TOKEN`
    const TEST_PACKET_ENCRYPTED: [u8; 288] = [33, 49, 1, 32, 0, 0, 0, 0, 7, 91, 205, 21, 0, 0, 130, 53, 81, 180, 22,
        217, 153, 170, 167, 40, 32, 146, 105, 247, 12, 100, 142, 33, 106, 181, 135, 51, 217, 45, 5, 161, 218, 157, 162,
        191, 123, 172, 179, 92, 118, 214, 164, 158, 202, 137, 55, 99, 86, 113, 140, 115, 30, 219, 73, 188, 83, 101, 118,
        13, 208, 107, 58, 221, 170, 53, 12, 55, 240, 22, 119, 42, 218, 54, 17, 248, 105, 30, 230, 206, 236, 78, 51, 248,
        124, 178, 211, 13, 131, 59, 70, 249, 240, 186, 42, 39, 225, 107, 109, 8, 90, 55, 8, 128, 85, 198, 57, 110, 126,
        63, 110, 67, 136, 208, 120, 29, 244, 40, 74, 236, 164, 72, 168, 14, 54, 18, 51, 221, 154, 52, 192, 253, 16, 12,
        111, 206, 227, 75, 200, 73, 246, 199, 76, 149, 46, 126, 176, 122, 82, 235, 9, 173, 87, 163, 176, 46, 185, 194,
        224, 209, 26, 217, 244, 172, 121, 64, 102, 139, 226, 202, 48, 34, 129, 252, 28, 135, 175, 110, 203, 220, 19,
        196, 80, 135, 229, 71, 100, 147, 120, 67, 37, 150, 25, 241, 171, 176, 217, 111, 136, 44, 80, 152, 239, 247, 139,
        209, 182, 127, 180, 31, 149, 150, 78, 92, 217, 36, 101, 157, 128, 122, 241, 239, 109, 71, 46, 204, 12, 119, 195,
        110, 213, 189, 13, 158, 95, 49, 172, 88, 59, 11, 227, 145, 3, 48, 234, 142, 247, 56, 164, 175, 43, 43, 35, 73,
        234, 100, 47, 247, 56, 127, 209, 217, 29, 5, 109, 159, 21, 32, 85, 86, 48, 55, 217, 51, 11, 132, 138, 123, 89,
        107];

    /// Discover response packet containing the `TEST_TOKEN` in the md5 field
    const TEST_PACKET_DISCOVERY_RESPONSE: [u8; 32] = [0x21, 0x31, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x07, 0x5b, 0xcd,
        0x15, 0x00, 0x00, 0x82, 0x35, 0x49, 0x73, 0x4f, 0x77, 0x54, 0x73, 0x64, 0x64, 0x6c, 0x48, 0x34, 0x73, 0x6b,
        0x6a, 0x6b, 0x50];

    #[test]
    fn test_parsing()
    {
        // Discover broadcast
        let packet = MiPacket::parse(&MI_DISCOVER_PACKET).unwrap();
        assert_eq!(packet.reserved, 0xffffffff);
        assert_eq!(packet.device_id, 0xffffffff);
        assert_eq!(packet.stamp, 0xffffffff);
        assert_eq!(packet.payload.len(), 0);

        // Discover response
        let packet = MiPacket::parse(&TEST_PACKET_DISCOVERY_RESPONSE).unwrap();
        assert_eq!(packet.reserved, 0);
        assert_eq!(packet.device_id, TEST_DEVICE_ID);
        assert_eq!(packet.stamp, TEST_STAMP);
        assert_eq!(packet.md5, TEST_TOKEN);
        assert_eq!(packet.payload.len(), 0);

        // test error
        let _packet_error = MiPacket::parse(&MI_DISCOVER_PACKET[..MI_DISCOVER_PACKET.len()-1]).unwrap_err();
    }

    #[test]
    fn test_packing() {
        let mut buffer = [0u8; TEST_PACKET_PLAINTEXT.len()];
        let mut packet = MiPacket::new(TEST_DEVICE_ID, TEST_STAMP);

        // Add payload
        packet.payload.extend_from_slice(TEST_PAYLOAD);

        // Serialize the MiPacket toe a given buffer
        let bytecount = packet.pack(&mut buffer, &TEST_TOKEN).unwrap();
        assert_eq!(&buffer[..bytecount], &TEST_PACKET_PLAINTEXT[..]);
    }

    #[test]
    fn test_encryption() {
        let mut buffer = [0u8; TEST_PACKET_ENCRYPTED.len()];
        let mut packet = MiPacket::new(TEST_DEVICE_ID, TEST_STAMP);

        // Add payload
        packet.payload.extend_from_slice(TEST_PAYLOAD);

        // Test encrypting
        assert!(packet.encrypt(&TEST_TOKEN));
        let bytecount = packet.pack(&mut buffer, &TEST_TOKEN).unwrap();
        assert_eq!(&buffer[..bytecount], &TEST_PACKET_ENCRYPTED[..]);

        // Test decrypting
        assert!(packet.decrypt(&TEST_TOKEN));
        let bytecount = packet.pack(&mut buffer, &TEST_TOKEN).unwrap();
        assert_eq!(&buffer[..bytecount], &TEST_PACKET_PLAINTEXT[..]);
    }
}

