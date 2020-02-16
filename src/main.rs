#![allow(dead_code)]

extern crate log;
extern crate simple_logger;

fn main() {
    // Initialize logger
    simple_logger::init().unwrap();

    yasbit::run();
}
