// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use std::mem::MaybeUninit;
use std::str;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use time::macros::format_description;
use time::OffsetDateTime;

mod syscall {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/syscall.skel.rs"
    ));
}

use syscall::*;


// fn handle_event(_cpu: i32, data: &[u8]) {
//     let mut event = syscall::types::event::default();
//     plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

//     let now = if let Ok(now) = OffsetDateTime::now_local() {
//         let format = format_description!("[hour]:[minute]:[second]");
//         now.format(&format)
//             .unwrap_or_else(|_| "00:00:00".to_string())
//     } else {
//         "00:00:00".to_string()
//     };

//     let task = str::from_utf8(&event.task).unwrap();

//     println!(
//         "{:8} {:16} {:<7} {:<14}",
//         now,
//         task.trim_end_matches(char::from(0)),
//         event.pid,
//         event.delta_us
//     );
// }

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {
  

    let mut skel_builder = SyscallSkelBuilder::default();
    // if opts.verbose {
    //     skel_builder.obj_builder.debug(true);
    // }



    let open_skel = skel_builder.open()?;



    // Begin tracing
    let mut skel = open_skel.load()?;
    skel.attach()?;
    let perf = PerfBufferBuilder::new(&skel.maps_mut().events())
    .sample_cb(|_cpu, data: &[u8]| {
        let data: &Data = unsafe { &*(data.as_ptr() as *const Data) };
        handle_event(data);
    })
    .build()?;
    // println!("Tracing run queue latency higher than {} us", opts.latency);
    // println!("{:8} {:16} {:7} {:14}", "TIME", "COMM", "TID", "LAT(us)");

    // let perf = PerfBufferBuilder::new(skel.obj.map_mut("events").unwrap())
    // .sample_cb(|_cpu, data: &[u8]| {
    //     let data: &Data = unsafe { &*(data.as_ptr() as *const Data) };
    //     print_event(data);
    // })
    // .build()?;

loop {

     perf.poll(std::time::Duration::from_millis(100))?;
}
 
}


#[repr(C)]
struct Data {
    pid: u32,
    inum: u64,
    sysnbr: u64,
}

fn handle_event(data: &Data) {
    println!("PID: {} Inum: {} Sysnbr: {}", data.pid, data.inum, data.sysnbr);
}