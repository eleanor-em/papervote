#![feature(async_closure, decl_macro, assoc_char_funcs)]

pub mod wbb;
pub mod trustee;
pub mod common;
pub mod voter;

pub const APP_NAME: &'static str = "papervote";
