#![allow(dead_code)]

extern crate log;
extern crate simple_logger;

fn main() {
    // Initialize logger
    simple_logger::init_with_level(log::Level::Debug).unwrap();

    yasbit::run();
}
