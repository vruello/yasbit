use crate::block;
use crate::crypto;
use crate::crypto::Hashable;
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc;
use std::thread;
use std::time;

pub enum Message {
    Wait(Vec<crypto::Hash32>),
    Validate(block::Block),
    Timeout(crypto::Hash32),
}

pub fn timeout(sender: mpsc::Sender<Message>, hash: crypto::Hash32) {
    log::debug!("timeout launched for hash {:?}", hash);
    thread::sleep(time::Duration::from_secs(2));
    log::debug!("timeout end for hash {:?}", hash);
    sender.send(Message::Timeout(hash)).unwrap();
}

pub fn run(sender: mpsc::Sender<Message>, receiver: mpsc::Receiver<Message>) {
    let mut available: HashMap<crypto::Hash32, block::Block> = HashMap::new();
    let mut waiting = VecDeque::new();

    match receiver.recv().unwrap() {
        Message::Wait(hashes) => {
            log::debug!(
                "Waiting list, currently {} hashes, add {} hashes",
                waiting.len(),
                hashes.len()
            );
            waiting.extend(hashes);
            log::debug!(
                "Waiting list updated. Size {}. Head: {:?}..",
                waiting.len(),
                waiting
                    .iter()
                    .take(10)
                    .map(|hash| format!("{:?}", hash))
                    .collect::<Vec<String>>()
            );
        }
        _ => log::error!("Should have received a Wait message first."),
    }

    // This never ends
    loop {
        let next = waiting.pop_front().unwrap();
        log::debug!("Next block to validate is {:?}", next);

        if !available.contains_key(&next) {
            log::debug!("Block {:?} is not yet available.", next);
            // Launch timeout
            let sender_timeout = sender.clone();
            let sender_hash = next.clone();
            thread::spawn(move || timeout(sender_timeout, sender_hash));

            while !available.contains_key(&next) {
                loop {
                    match receiver.recv().unwrap() {
                        Message::Wait(hashes) => {
                            log::debug!(
                                "Waiting list, currently {} hashes, add {} hashes",
                                waiting.len(),
                                hashes.len()
                            );
                            waiting.extend(hashes);
                            log::debug!(
                                "Waiting list updated. Size {}. Head: {:?}..",
                                waiting.len(),
                                waiting
                                    .iter()
                                    .take(10)
                                    .map(|hash| format!("{:?}", hash))
                                    .collect::<Vec<String>>()
                            );
                        }
                        Message::Validate(block) => {
                            log::debug!("Block {:?} is available", block.hash());
                            available.insert(block.hash(), block);
                            break; // Tests again if now the block is available
                        }
                        Message::Timeout(hash) => {
                            log::debug!("Timeout for block {:?}", hash);
                            if hash == next {
                                log::error!(
                                    "Could not retrieve block {:?}. Ask another node...",
                                    hash
                                );
                                // TODO
                            }
                        }
                    }
                }
            }
        }

        // next is available
        log::debug!("Validate {:?}", next);
        let block = available.remove(&next).unwrap();
        // Validate block

        log::debug!("Validate block {:?}", block);
        // TODO
    }
}
