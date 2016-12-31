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

/*
	0 = upper -> lower [AaAa...]
	1 = lower -> upper [aAaA...]
*/
#[derive(RustcDecodable, RustcEncodable)]
struct RecivedPasswordStruct {
	pwd: String,
	site: String,
	choice: u8,
	max_length: u16
}

#[derive(RustcDecodable, RustcEncodable)]
struct SentPasswordStruct {
	pwd: String
}

/*
	Base64 struct example:
		{ "pwd":"John", "site":"google.com", "choice":0, "max_length":40 }
		eyAicHdkIjoiSm9obiIsICJzaXRlIjoiZ29vZ2xlLmNvbSIsICJjaG9pY2UiOjAsICJtYXhfbGVuZ3RoIjo0MCB9

		{ "pwd":"John", "site":"google.com", "choice":1, "max_length":40 }
		eyAicHdkIjoiSm9obiIsICJzaXRlIjoiZ29vZ2xlLmNvbSIsICJjaG9pY2UiOjEsICJtYXhfbGVuZ3RoIjo0MCB9
*/
fn main() {
	let mut is_argument_json_b64 = false;
	let mut argument_json = "".to_string();
	let mut is_argument_password = false;
	let mut argument_password = "".to_string();
	let mut is_argument_site = false;
	let mut argument_site = "".to_string();
	let mut is_argument_pattern = false;
	let mut argument_pattern = 0;
	let mut is_argument_max_length = false;
	let mut argument_max_length: u16 = 0;
	let args: Vec<String> = env::args().collect();
	let args_len = args.len();

	let mut recived_password_struct: RecivedPasswordStruct;

	for argument_index in 1..args_len {
		let current_argument = args.get(argument_index).unwrap();

		if "-help" == current_argument {
			println!("{:?}", "***************** List of required parameters(s) *****************");
			println!("{:?}", "There's two way to generate a password");
			println!("{:?}", "1:");
			println!("{:?}", "-jsonB64");
			println!("{:?}", "2: (Theses four parameters are MANDATORY");
			println!("{:?}", "-password AND -site AND -pattern AND -max_length");
			exit(0);
		}

		if args_len > argument_index + 1 {
			let argument: String = args.get(argument_index + 1).unwrap().clone();

			if "-jsonB64" == current_argument {
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
				argument_pattern = argument.chars().nth(0).unwrap() as u8;
			} else if "-max_length" == current_argument {
				is_argument_max_length = true;
				argument_max_length = argument.parse::<u16>().unwrap();
			}
		}
	}

	if is_argument_json_b64 {
		argument_json = decode_b64(argument_json);
		recived_password_struct = json::decode(&argument_json).unwrap();
	} else if !is_argument_site || !is_argument_pattern || !is_argument_password || !is_argument_max_length { //Make sure that the required parameters are initialized if not json
		panic!("{:?}", "All required parameters(s) must be set !");
	} else {
		recived_password_struct = RecivedPasswordStruct { pwd: argument_password.clone(), site: argument_site.clone(), choice: argument_pattern, max_length: argument_max_length };
	}

	print!("{}", generate_sentpasswordstruct_json(generate_password(recived_password_struct)));
}

//Generate the hash based on the received parameters
fn generate_password(recv_struct: RecivedPasswordStruct) -> String {
	let choice: u8 = recv_struct.choice;
	let max_length: u16 = recv_struct.max_length;

	let hashed: String = generate_hexed_hash_bytes(recv_struct.pwd + &recv_struct.site);
	let mut final_hash: String = "".to_string();

	if choice == 0 || choice == 1 {

		let mut index:u8 = 0;
		for mut b in hashed.chars() {
			let b_as_uint: u8 = b as u8;

			if is_alphabet_character(b_as_uint) {
				if index & 1 == choice {
					b = invert_case(b_as_uint) as char;
				} 

				index += 1;
			}

			final_hash.push(b);
		}
	}

	if max_length > 0 {
		final_hash = final_hash[0..max_length as usize].to_string();
	}

	return final_hash;
}

fn generate_sentpasswordstruct_json(pwd : String) -> String {
	let sent_password_struct: SentPasswordStruct = SentPasswordStruct { pwd: pwd};
	return encode_str_to_b64(json::encode(&sent_password_struct).unwrap().to_string());
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

	if !is_alphabet_character(case) {
		return case;
	}

	let mut is_lowercase = 1;

	if (case & 32) == 32 {
		is_lowercase = 0;
	}

	return case & 64 | is_lowercase << 5 | case & 31;
}

fn is_alphabet_character(case : u8) -> bool {
	return (case >= 65 && case <= 90) || (case >= 97 && case <= 122);
}