use ebpf_tracker_events::StreamRecord;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    BpftraceStdout,
    PerfEventArray,
    RingBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImplementationStatus {
    Available,
    Scaffold,
    Planned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportPlan {
    pub kind: TransportKind,
    pub status: ImplementationStatus,
    pub notes: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureEnvelope {
    pub timestamp_unix_ms: u64,
    pub cpu: u32,
    pub payload: Vec<u8>,
}

pub trait EventDecoder {
    fn decode(&self, envelope: &CaptureEnvelope) -> Result<StreamRecord, String>;
}

pub fn default_transport_plan() -> Vec<TransportPlan> {
    vec![
        TransportPlan {
            kind: TransportKind::BpftraceStdout,
            status: ImplementationStatus::Available,
            notes: "Current release path: bpftrace prints trace lines that the CLI turns into events.",
        },
        TransportPlan {
            kind: TransportKind::PerfEventArray,
            status: ImplementationStatus::Scaffold,
            notes: "Reserved for native kernel-to-userspace event delivery when we outgrow stdout parsing.",
        },
        TransportPlan {
            kind: TransportKind::RingBuf,
            status: ImplementationStatus::Planned,
            notes: "Preferred future path when strict cross-CPU ordering matters for streamed events.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{default_transport_plan, ImplementationStatus, TransportKind};

    #[test]
    fn transport_plan_lists_current_and_future_paths() {
        let plan = default_transport_plan();

        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].kind, TransportKind::BpftraceStdout);
        assert_eq!(plan[0].status, ImplementationStatus::Available);
        assert_eq!(plan[1].kind, TransportKind::PerfEventArray);
        assert_eq!(plan[1].status, ImplementationStatus::Scaffold);
        assert_eq!(plan[2].kind, TransportKind::RingBuf);
        assert_eq!(plan[2].status, ImplementationStatus::Planned);
    }
}
