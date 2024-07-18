#![no_std]
#![no_main]

use core::{mem, slice};

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_long,
    helpers::{bpf_get_current_task, bpf_probe_read_kernel, gen::bpf_get_current_pid_tgid},
    macros::{map, raw_tracepoint, tracepoint, xdp},
    maps::{HashMap, PerfEventArray},
    programs::{RawTracePointContext, TracePointContext, XdpContext},
    EbpfContext,
};
use aya_log_ebpf::{debug, info};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use ebpf_demo_common::{SysCallLog, ForkLogs,NetworkTraceLogs};

#[repr(C)]
pub struct Key {
    pid: u32,
}

#[repr(C)]
pub struct Value {
    parent_pid: u32,
}

// #[no_mangle]
// static mut PID_MAP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map(name = "PROCESS_TREE")]
static mut PROCESS_TREE: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map(name = "SYSCALLS")]
static mut SYSCALLS: HashMap<i32, i32> = HashMap::<i32, i32>::with_max_entries(1024, 0);


#[map]
pub static FORK_EVENTS: PerfEventArray<ForkLogs> = PerfEventArray::new(0);
#[map]
pub static SYS_CALL_EVENTS: PerfEventArray<SysCallLog> = PerfEventArray::new(0);

#[map]
pub static NETWORK_EVENTS: PerfEventArray<NetworkTraceLogs> = PerfEventArray::new(0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sched_process_fork(ctx: TracePointContext) -> Result<u32, u32> {
    let child_pid: u32 = unsafe { ctx.read_at(44).map_err(|_| 100u32)? };
    let parent_pid: u32 = unsafe { ctx.read_at(24).map_err(|_| 100u32)? };
    
        unsafe {
            PROCESS_TREE.insert(&child_pid, &parent_pid,0).map_err(|_|100u32)?;
        };
    

    Ok(0)
}


#[raw_tracepoint]
pub fn try_raw_tracepoint(ctx: RawTracePointContext) -> u32 {
    match unsafe {try_tracepoint_syscalls(ctx)} {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_tracepoint_syscalls(ctx: RawTracePointContext) -> Result<u32, u32> {
  
 
    let pid = ctx.pid();

    // //if  let Some(value) = PID_MAP.get(&pid) {
        let args = unsafe { slice::from_raw_parts(ctx.as_ptr() as *const usize, 2) };
        let syscall = args[1] as u64;
        let syscall_nbr = syscall as u32;

        let mut current_pid = pid;
        let mut stack: [u32; 10] = [0; 10];  // Limit the depth to 10 to avoid loops
        let mut index = 0;
    
        while index < 10 {
            if let Some(parent_pid) = PROCESS_TREE.get(&current_pid) {
                stack[index] = current_pid;
                current_pid = *parent_pid;
                index += 1;
            } else {
                break;
            }
        }
    
        let root_pid = if index > 0 { stack[index-1] as u32 } else { 0 as u32 };
        let log_entry: SysCallLog = SysCallLog {
            pid: root_pid,
            syscall_nbr,
        };
        SYS_CALL_EVENTS.output(&ctx, &log_entry, 0);
    Ok(0)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let ingress_if_index = unsafe { (*ctx.ctx).ingress_ifindex };

    match unsafe { *ethhdr }.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv4hdr).src_addr };
            let dest_addr = unsafe { (*ipv4hdr).dst_addr };

            let (source_port, dest_port, syn, ack) = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    (
                        u16::from_be(unsafe { (*tcphdr).source }),
                        u16::from_be(unsafe { (*tcphdr).dest }),
                        unsafe { (*tcphdr).syn() },
                        unsafe { (*tcphdr).ack() },
                    )
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    (
                        u16::from_be(unsafe { (*udphdr).source }),
                        u16::from_be(unsafe { (*udphdr).dest }),
                        2,
                        2,
                    )
                }
                _ => return Ok(xdp_action::XDP_PASS),
            };
            let log_entry = NetworkTraceLogs {
                saddr: source_addr,
                daddr: dest_addr,
                sport: source_port,
                dport: dest_port,
                syn,
                ack,
                if_index: ingress_if_index,
            };
            NETWORK_EVENTS.output(&ctx, &log_entry, 0);

            //info!(&ctx, "SRC IP: {:i}, SRC PORT: {} Ingress ifindex {}", u32::from_be(source_addr), source_port,ingress_if_index);
        }
        EtherType::Ipv6 => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };

            let source_port = match unsafe { (*ipv6hdr).next_hdr } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                    u16::from_be(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                    u16::from_be(unsafe { (*udphdr).source })
                }
                _ => return Ok(xdp_action::XDP_PASS),
            };

            //info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);
        }
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
