use crate::scene::ir::{ChunkTrace, Confidence, DecodedChunkRecord, DecodedEvent, LinkOp};

pub(crate) fn recover_links_from_cons(decoded_chunks: &[DecodedChunkRecord]) -> Vec<LinkOp> {
    let mut links = Vec::new();

    for decoded in decoded_chunks {
        if decoded.chunk_ref.form != "CONS" {
            continue;
        }
        let trace = Some(ChunkTrace {
            form: decoded.chunk_ref.form.clone(),
            tag: decoded.chunk_ref.tag.clone(),
            node_offset: decoded.chunk_ref.node_offset,
            chunk_aux: decoded.chunk_ref.chunk_aux,
            child_alignment: decoded.chunk_ref.child_alignment,
            child_header_size: decoded.chunk_ref.child_header_size,
        });
        for ev in &decoded.events {
            match ev {
                DecodedEvent::Connect { src, dst, mode } => {
                    links.push(LinkOp::Connect {
                        src: src.clone(),
                        dst: dst.clone(),
                        mode: *mode,
                        trace: trace.clone(),
                        confidence: Confidence::Exact,
                    });
                }
                DecodedEvent::Relationship { kind, head, tail } => {
                    links.push(LinkOp::Relationship {
                        kind: kind.clone(),
                        head: head.clone(),
                        tail: tail.clone(),
                        trace: trace.clone(),
                        confidence: Confidence::Exact,
                    });
                }
                _ => {}
            }
        }
    }

    links
}
