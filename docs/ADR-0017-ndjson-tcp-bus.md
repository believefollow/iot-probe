# ADR-0017 NDJSON 帧流新增 `bus.type=tcp`(任务卡 A5 配套)

- 状态:已采纳(2026-11-21)
- 背景:IEC 104 从机模拟(A5)的 APDU 需要进入统一管线,而 104 的通道识别只挂在
  `Proto::Tcp` 记录上(dissect/mod.rs:TCP 分支要求 ≥2 个合法 APDU 且覆盖率过半)。
  契约 frame.schema 的 `bus.type` 枚举原本只有 can/canfd/uart/ecat,没有 TCP 字节流形态。
- 决策:`bus.type` 枚举追加 `"tcp"`;LiveSession 映射 Proto::Tcp(通道 class=3,默认标签 TCP{n});
  live_frame_to_jsonl 输出 `"tcp"`。NDJSON 每行 = 一个完整 APDU/应用报文。
- 影响:
  - 契约:仅枚举追加,旧录制文件(不含 tcp)完全兼容;新文件在旧版本软件里会判坏行
    (可接受:旧版本也不解析 104)。
  - 解析:tcp 记录走既有 104/MQTT/HTTP/自定义/裸字节识别链,零改动。
- 不做:raw 二进制 TCP 长流仍走 rtu_tcp 专用路径(RTU-over-TCP),本枚举只承载
  "已定界、一行一帧"的 TCP 应用层帧。
