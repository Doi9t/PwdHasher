/*
 *    Copyright 2014 - 2016 Yannick Watier
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

extern crate crypto; //https://docs.rs/crate/rust-crypto
extern crate rustc_serialize;

use std::str;
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use rustc_serialize::json;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::base64::FromBase64; //data.from_base64()

/*
	Number range (dec): 48 <=> 57
	Letters (dec): 65 <=> 90 && 97 <=> 122 
	 - When 6th byte == 1, It's a lower
*/

#[derive(RustcDecodable, RustcEncodable)]
struct RecivedPasswordStruct {
	value: String,
	choice: u8
}


#[derive(RustcDecodable, RustcEncodable)]
struct SentPasswordStruct {
	pwd: String
}

fn main() {

	//Struct to json
	let pwd: RecivedPasswordStruct = RecivedPasswordStruct { value: "superPassword".to_string(), choice: 18 };
	let user_to_json = json::encode(&pwd).unwrap();
    println!("{:?}", user_to_json);

    //Json string to Stuct
	let password: RecivedPasswordStruct = json::decode(&user_to_json).unwrap();
	let entered_password = password.value;
	println!("{:?}", entered_password);


	//String json to base64
	let str_to_b64 = encode_str_to_b64(user_to_json);
	println!("encode_str_to_b64 -> {:?}", str_to_b64);

	//Base64 string to json string
	println!("decode_b64_to_json -> {:?}", decode_b64_to_json(str_to_b64));


	println!("generate_sentpasswordstruct_json -> {:?}", generate_sentpasswordstruct_json("superPassword".to_string()));


	println!("{} -------", "generate_raw_hash_bytes".to_string());
	for b in generate_raw_hash_bytes(entered_password) {
		print!("{}, ", b);
	}

}

fn generate_sentpasswordstruct_json(pwd : String) -> String {

	let string_hexed_hash = generate_hexed_hash_bytes(pwd);

	let sent_password_struct: SentPasswordStruct = SentPasswordStruct { pwd: string_hexed_hash.to_string()};
	return json::encode(&sent_password_struct).unwrap().to_string();
}

fn encode_str_to_b64(json: String) -> String {
	return json.as_bytes().to_base64(base64::STANDARD);
}

fn decode_b64_to_json(json: String) -> String {
	return vec_to_string(json.from_base64().unwrap());
}

fn vec_to_string(value: Vec<u8>) -> String {
	return str::from_utf8(&value).unwrap().to_string();
}

//Return the real bytes
fn generate_raw_hash_bytes(entered_password: String) -> Vec<u8> {
	let mut sha = Sha512::new();
	sha.input_str(&entered_password);

	let mut bytes = vec![0; 64];
	sha.result(bytes.as_mut_slice());

	return bytes;
}

//Return the hex values of the hash
fn generate_hexed_hash_bytes(entered_password: String) -> String {
	let mut sha = Sha512::new();
	sha.input_str(&entered_password);

	return sha.result_str();
}
