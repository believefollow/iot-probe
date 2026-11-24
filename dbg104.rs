use iotprobe_core::ingest::read_file;
#[test]
fn dbg_104_scan() {
    let src = read_file(std::path::Path::new("tests/data/iec104.pcap")).unwrap();
    for (i, r) in src.records.iter().enumerate() {
        let (apdus, junk) = iotprobe_core::dissect::iec104::scan(&r.data);
        println!("rec{i}: {}B apdus={} junk={}", r.data.len(), apdus.len(), junk);
        println!("  head: {}", r.data[..48.min(r.data.len())].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "));
        for (o, l, k) in apdus.iter() {
            println!("  apdu @{o} len{l} kind{k}");
        }
        // junk 区间推导
        let mut covered = vec![];
        for (o, l, _) in &apdus {
            covered.push((*o, o + l));
        }
        covered.sort();
        let mut cur = 0usize;
        for (a, b) in covered {
            if a > cur {
                println!("  junk @{cur}..{a}: {}", r.data[cur..a.min(r.data.len())].iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" "));
            }
            cur = cur.max(b);
        }
        if cur < r.data.len() {
            println!("  junk @{cur}..{}: {}", r.data.len(), r.data[cur..].iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" "));
        }
    }
}
