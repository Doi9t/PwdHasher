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

use std::env;
use std::str;
use std::process::exit;
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use rustc_serialize::json;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::base64::FromBase64;

#[derive(RustcDecodable, RustcEncodable)]
struct RecivedPasswordStruct {
	pwd: String,
	site: String,
	choice: u8
}

#[derive(RustcDecodable, RustcEncodable)]
struct SentPasswordStruct {
	pwd: String
}

/*
	Base64 struct example:
		{ "pwd":"John", "site":"google.com", "choice":15 }
		eyAicHdkIjoiSm9obiIsICJzaXRlIjoiZ29vZ2xlLmNvbSIsICJjaG9pY2UiOjE1IH0=
*/

fn main() {
	let mut is_argument_json = false;
	let mut is_argument_json_b64 = false;
	let mut argument_json = "".to_string();
	let mut is_argument_password = false;
	let mut argument_password = "".to_string();
	let mut is_argument_site = false;
	let mut argument_site = "".to_string();
	let mut is_argument_pattern = false;
	let mut argument_pattern = "".to_string();
	let args: Vec<String> = env::args().collect();
	let args_len = args.len();

	for argument_index in 1..args_len {
		let current_argument = args.get(argument_index).unwrap();

		if "-help" == current_argument {
			println!("{:?}", "***************** List of required parameters(s) *****************");
			println!("{:?}", "There's two way to generate a password");
			println!("{:?}", "1:");
			println!("{:?}", "-json OR -jsonB64");
			println!("{:?}", "2: (Theses three parameters are MANDATORY");
			println!("{:?}", "-password AND -site AND -pattern");
			exit(0);
		}

		if args_len > argument_index + 1 {
			let argument = args.get(argument_index + 1).unwrap().clone();
			if "-json" == current_argument {
				is_argument_json = true;
				argument_json = argument;
			} else if "-jsonB64" == current_argument {
				is_argument_json_b64 = true;
				argument_json = argument;
			} else if "-password" == current_argument {
				is_argument_password = true;
				argument_password = argument;
			} else if "-site" == current_argument {
				is_argument_site = true;
				argument_site = argument;
			} else if "-pattern" == current_argument {
				is_argument_pattern = true;
				argument_pattern = argument;
			}
		}
	}

	if is_argument_json_b64 {
		argument_json = decode_b64(argument_json);
	}

	if (is_argument_json_b64 || is_argument_json) {

		let recived_password_struct: RecivedPasswordStruct = json::decode(&argument_json).unwrap();
		let pwd: String = recived_password_struct.pwd;
		let site: String = recived_password_struct.site;
		let choice: u8 = recived_password_struct.choice;

		let hashed: String = generate_hexed_hash_bytes(pwd + &site);


	} else if !is_argument_site || !is_argument_pattern || !is_argument_password { //Make sure that the required parameters are initialized if not json
		panic!("{:?}", "All required parameters(s) must be set !");
	} else { 
		//is_argument_site, is_argument_pattern & is_argument_password are set
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

fn decode_b64(json: String) -> String {
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

/*
	Number range (dec): 48 <=> 57
	Letters (dec): 65 <=> 90 && 97 <=> 122 
		- When 6th byte == 1, It's a lower
*/
fn invert_case(case : u8) -> u8  {

	if !((case >= 65 && case <= 90) || (case >= 97 && case <= 122)) {
		panic!("The parameter {} must be a letter !", case);
	}

	let mut is_lowercase = 1;

	if (case & 32) == 32 {
		is_lowercase = 0;
	}

	return case & 64 | is_lowercase << 5 | case & 31;
}