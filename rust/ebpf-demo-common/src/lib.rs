#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]

pub struct NetworkTraceLogs {
    pub saddr: u32, // source address
    pub daddr: u32, // destination address
    pub sport: u16, //src port
    pub dport: u16, // dest port
    pub syn: u16,
    pub ack: u16,
    // pub inum: u32, // i node numbner
    pub if_index: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]

pub struct SysCallLog {
    pub pid: u32,
    pub syscall_nbr: u32,
    pub inum: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]

pub struct ForkLogs {
    pub childid: u32,
    pub parentid: u32,
}


#[cfg(feature = "user")]
pub mod user {
    use super::*;
    unsafe impl aya::Pod for NetworkTraceLogs {}
    unsafe impl aya::Pod for ForkLogs {}
    unsafe impl aya::Pod for SysCallLog {}
}

unsafe impl Send for NetworkTraceLogs {}
unsafe impl Send for ForkLogs {}
unsafe impl Send for SysCallLog {}
