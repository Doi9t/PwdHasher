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
	********* Patterns availables *********
	0 = upper -> lower [AaAa...]
	1 = lower -> upper [aAaA...]
	2 = all uppercases
	3 = all lowercases
*/
#[derive(RustcDecodable, RustcEncodable)]
struct RecivedPasswordStruct {
	pwd: String,
	site: String, //The website were the password will be used
	choice: u8, //The pattern choice
	max_length: u16, //The maximum length of the generated password (containing the byte paddings)
	pre_byte_padding: String, //The string to be appended before the byte
	post_byte_padding: String //The string to be appended after the byte
}

#[derive(RustcDecodable, RustcEncodable)]
struct SentPasswordStruct {
	pwd: String
}

/*
	Base64 struct input example (for tests & debug):
		{ "pwd":"John", "site":"google.com", "choice":0, "max_length":40, "pre_byte_padding":"!~", "post_byte_padding":"~!" }
		base64 -> eyAicHdkIjoiSm9obiIsICJzaXRlIjoiZ29vZ2xlLmNvbSIsICJjaG9pY2UiOjAsICJtYXhfbGVuZ3RoIjo0MCwgInByZV9ieXRlX3BhZGRpbmciOiIhfiIsICJwb3N0X2J5dGVfcGFkZGluZyI6In4hIiB9
*/
fn main() {
	let mut argument_choice = 0;
	let mut argument_json = "".to_string();
	let mut argument_max_length: u16 = 0;
	let mut argument_password = "".to_string();
	let mut argument_post_byte_padding = "".to_string();
	let mut argument_pre_byte_padding = "".to_string();
	let mut argument_site = "".to_string();
	let mut is_argument_choice = false;
	let mut is_argument_json_b64 = false;
	let mut is_argument_max_length = false;
	let mut is_argument_password = false;
	let mut is_argument_site = false;
	let mut is_post_byte_padding = false;
	let mut is_pre_byte_padding = false;

	let args: Vec<String> = env::args().collect();
	let args_len = args.len();

	let recived_password_struct: RecivedPasswordStruct;

	for argument_index in 1..args_len {
		let current_argument = args.get(argument_index).unwrap();

		if "-help" == current_argument {
			println!("{}", "***************** List of required parameters(s) *****************");
			println!("{}", "There's two way to generate a password");
			println!("{}", "1: -jsonB64");
			println!("{}", "2: -password, -site, -choice, -max_length, -post_byte_padding and -pre_byte_padding (Theses six parameters are MANDATORY if not using the first method)\n");
			println!("{}", "***************** Patterns availables (-choice [number]) *****************");
			println!("{}", "0 = upper -> lower [AaAa...]");
			println!("{}", "1 = lower -> upper [aAaA...]");
			println!("{}", "2 = all uppercases [AAAA...]");
			println!("{}", "3 = all lowercases [aaaa...]");
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
			} else if "-choice" == current_argument {
				is_argument_choice = true;
				argument_choice = argument.chars().nth(0).unwrap() as u8;
			} else if "-max_length" == current_argument {
				is_argument_max_length = true;
				argument_max_length = argument.parse::<u16>().unwrap();
			} else if "-post_byte_padding" == current_argument {
				is_post_byte_padding = true;
				argument_post_byte_padding = argument;
			} else if "-pre_byte_padding" == current_argument {
				is_pre_byte_padding = true;
				argument_pre_byte_padding = argument;
			}
		}
	}

	if is_argument_json_b64 {
		argument_json = decode_b64(argument_json);
		recived_password_struct = json::decode(&argument_json).unwrap();
	} else if !is_argument_site || !is_argument_choice || !is_argument_password || !is_argument_max_length || !is_post_byte_padding || !is_pre_byte_padding { //Make sure that the required parameters are initialized if not json
		panic!("{}", "All required parameters(s) must be set !");
	} else {
		recived_password_struct = RecivedPasswordStruct 
		{ 
			pwd: argument_password.clone(), 
			site: argument_site.clone(), 
			choice: argument_choice, 
			max_length: argument_max_length,
			pre_byte_padding: argument_pre_byte_padding,
			post_byte_padding: argument_post_byte_padding
		};
	}

	print!("{}", generate_sentpasswordstruct_json(generate_password(recived_password_struct)));
}

//Generate the hash based on the received parameters
fn generate_password(recv_struct: RecivedPasswordStruct) -> String {
	let choice: u8 = recv_struct.choice;
	let max_length: u16 = recv_struct.max_length;

	let pre_byte_padding: String = recv_struct.pre_byte_padding;
	let pre_byte_padding_len: u16 = pre_byte_padding.len() as u16;

	let post_byte_padding: String = recv_struct.post_byte_padding;
	let post_byte_padding_len: u16 = post_byte_padding.len() as u16;

	let max_hash_char_len: u8 = (max_length / (pre_byte_padding_len + post_byte_padding_len + 1)) as u8;

	if max_length < 1 {
		panic!("The attribute max_length must be > 1 !  (Currently {})", max_length);
	}

	let hashed: String = generate_hexed_hash_bytes(recv_struct.pwd + &recv_struct.site)[0..max_length as usize].to_string();
	let mut final_hash: String = "".to_string();
		let mut index:u8 = 0; 
		for mut b in hashed.chars() {

			let b_as_uint: u8 = b as u8;

			if choice == 0 || choice == 1 { //0 = upper -> lower [AaAa...] | 1 = lower -> upper [aAaA...]
					if is_alphabet_character(b_as_uint) {
						if index & 1 == choice {
							b = invert_case(b_as_uint) as char;
						} 
					}

			} else if choice == 2 { //Uppercase
				if is_character_lowercase(b_as_uint) {
					b = invert_case(b_as_uint) as char;
				}

			} else if choice == 3 { //Lowercase
				if !is_character_lowercase(b_as_uint) {
					b = invert_case(b_as_uint) as char;
				}
			}

			if pre_byte_padding_len != 0 {
				final_hash += &pre_byte_padding;
			}

			final_hash.push(b);

			if post_byte_padding_len != 0 {
				final_hash += &post_byte_padding;
			}

			if (max_hash_char_len - 1) == index {
				break;
			}

			index += 1;
		}

	return final_hash;
}

//Create a new string containing the json (with base64)
fn generate_sentpasswordstruct_json(pwd : String) -> String {
	return encode_str_to_b64(json::encode(&SentPasswordStruct { pwd: pwd }).unwrap().to_string());
}

//Encode a string into a base64 string
fn encode_str_to_b64(json: String) -> String {
	return json.as_bytes().to_base64(base64::STANDARD);
}

//Decode the base64 string into a string
fn decode_b64(json: String) -> String {
	return vec_to_string(json.from_base64().unwrap());
}

//Convert a vector of u8 into a string
fn vec_to_string(value: Vec<u8>) -> String {
	return str::from_utf8(&value).unwrap().to_string();
}

//Return the hex values of the hash
fn generate_hexed_hash_bytes(entered_password: String) -> String {
	let mut sha = Sha512::new();
	sha.input_str(&entered_password);

	return sha.result_str();
}

//Invert the character case
fn invert_case(case : u8) -> u8  {

	if !is_alphabet_character(case) {
		return case;
	}

	let mut is_lowercase = 1;

	if is_character_lowercase(case) {
		is_lowercase = 0;
	}

	return case & 64 | is_lowercase << 5 | case & 31;
}

fn is_character_lowercase(case: u8) -> bool {
	return is_alphabet_character(case) && (case & 32) == 32;
}

fn is_alphabet_character(case : u8) -> bool {
	return (case >= 65 && case <= 90) || (case >= 97 && case <= 122);
}