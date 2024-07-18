use std::net::Ipv4Addr;
use std::sync::Arc;

use aya::maps::{AsyncPerfEventArray, HashMap};
use aya::programs::{CgroupSkb, CgroupSkbAttachType, RawTracePoint, TracePoint, Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{debug, info, warn};
use tokio::{signal, task};
use ebpf_demo_common::{SysCallLog, NetworkTraceLogs};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf-demo"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf-demo"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program_sys_calls: &mut RawTracePoint = bpf.program_mut("try_raw_tracepoint").unwrap().try_into()?;
             
    if let Err(e) = program_sys_calls.load(){ 
        println!("Failed to load  program_sys_calls {}", e);
        
    };

    if let Err(e) = program_sys_calls.attach("sys_enter") {
        println!("Failed to attach sys_enter {}", e);
    };

    let program_sch_process: &mut TracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
             
    if let Err(e) = program_sch_process.load(){ 
        println!("Failed to load  program_sch_process {}", e);
        
    };

    if let Err(e) = program_sch_process.attach("sched","sched_process_fork") {
        println!("Failed to attach sched_process_fork {}", e);
    };

    let PROCESS_TREE: Arc<HashMap<_, u32, u32>> =
    Arc::new(HashMap::try_from(bpf.take_map("PROCESS_TREE").unwrap())?);
    
    // let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    // ///sys/fs/cgroup//system.slice/docker-fbc411e743aa89de421746b3fc92e4fa475d0f2dc92967fb39c2f78574799701.scope/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod5f413373_db04_4240_a645_993a3fbcffc3.slice/cri-containerd-e0d51863af3b89d990370749541ea926418346f6f1c92c255e4862f6a1c04d80.scope

    // program.load()?;
    // let interface = &opt.iface;
    // println!("interface {}", interface);
    // // let cpath = format!("/sys/fs/cgroup/{}",opt.iface);
    // // info!("cgrp {}",cpath);
    // // let cgroup_file= std::fs::File::open(cpath)?;
    // program.attach(&interface, XdpFlags::default());

    // let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("NETWORK_EVENTS").unwrap())?;
    // for cpu_id in online_cpus()? {
    //     let mut perf_buffer = perf_array.open(cpu_id, None)?;

    //     task::spawn(async move {
    //         let mut buffers = (0..10)
    //             .map(|_| BytesMut::with_capacity(1024))
    //             .collect::<Vec<_>>();

    //         loop {
    //             let events = perf_buffer.read_events(&mut buffers).await.unwrap();
    //             for buf in buffers.iter_mut().take(events.read) {
    //                 let ptr = UserObj(buf.as_ptr() as *const NetworkTraceLogs);
    //                 let data = unsafe { ptr.as_ptr().read_unaligned() };
  
                    
    //                 println!(
    //                     "source {}:{}, destination {}:{} ifindex {}, syn {}, ack {}",Ipv4Addr::from(data.saddr.to_be()).to_string(), data.sport, Ipv4Addr::from(data.daddr.to_be()).to_string(), data.dport,
    //                     data.if_index,data.syn, data.ack
    //                 );
    //             }
    //         }
    //     });
    // }


    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("SYS_CALL_EVENTS").unwrap())?;
    for cpu_id in online_cpus()? {
        let mut perf_buffer = perf_array.open(cpu_id, None)?;
        let p =  Arc::clone(&PROCESS_TREE);
        task::spawn(
            
            async move {
            
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
           
            loop {
               
                let events = perf_buffer.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = SyscallObj(buf.as_ptr() as *const SysCallLog);
                    let data = unsafe { ptr.as_ptr().read_unaligned() };

                    if data.pid > 0{
                    
                        for i in p.iter().into_iter() {
                            if let Ok(value) = i {
                                println!( "Key {}, value {}", value.0, value.1);
                            }
                        }

                    println!(
                        "pid {} syscallnbr {}",data.pid, data.syscall_nbr
                    );
                    println!( "---------------------------------------------");
                }
                
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

struct UserObj(*const NetworkTraceLogs);
// SAFETY: Any user data object must be safe to send between threads.
unsafe impl Send for UserObj {}

impl UserObj {
    fn as_ptr(&self) -> *const NetworkTraceLogs {
        self.0
    }
}

struct SyscallObj(*const SysCallLog);
// SAFETY: Any user data object must be safe to send between threads.
unsafe impl Send for SyscallObj {}

impl SyscallObj {
    fn as_ptr(&self) -> *const SysCallLog {
        self.0
    }
}
