use crate::scene::ir::{
    ChunkTrace, Confidence, DecodedChunkRecord, DecodedEvent, SelectBlock, SelectBlockNote,
    SelectBlockOp,
};

pub(crate) fn recover_select_blocks(decoded_chunks: &[DecodedChunkRecord]) -> Vec<SelectBlock> {
    let mut blocks = Vec::new();
    let mut cursor = 0usize;

    while cursor < decoded_chunks.len() {
        let first = &decoded_chunks[cursor];
        if first.chunk_ref.form != "SLCT" {
            cursor += 1;
            continue;
        }
        let node_offset = first.chunk_ref.node_offset;
        let mut target: Option<String> = None;
        let mut block_ops = Vec::new();
        let mut block_notes = Vec::new();
        let mut trace = Some(ChunkTrace {
            form: "SLCT".to_string(),
            tag: "SLCT".to_string(),
            node_offset,
            chunk_aux: None,
            child_alignment: first.chunk_ref.child_alignment,
            child_header_size: first.chunk_ref.child_header_size,
        });

        while cursor < decoded_chunks.len()
            && decoded_chunks[cursor].chunk_ref.form == "SLCT"
            && decoded_chunks[cursor].chunk_ref.node_offset == node_offset
        {
            let decoded = &decoded_chunks[cursor];
            for ev in &decoded.events {
                match ev {
                    DecodedEvent::SelectTarget { target: t } => target = Some(t.clone()),
                    DecodedEvent::AddAttr(op) => block_ops.push(SelectBlockOp::AddAttr(op.clone())),
                    DecodedEvent::SetAttr(op) => block_ops.push(SelectBlockOp::SetAttr(op.clone())),
                    _ => {}
                }
            }
            trace = Some(ChunkTrace {
                form: "SLCT".to_string(),
                tag: decoded.chunk_ref.tag.clone(),
                node_offset,
                chunk_aux: decoded.chunk_ref.chunk_aux,
                child_alignment: decoded.chunk_ref.child_alignment,
                child_header_size: decoded.chunk_ref.child_header_size,
            });
            cursor += 1;
        }

        let (target, confidence) = match target {
            Some(target) => (target, Confidence::Exact),
            None => {
                let placeholder = format!(":__missing_slct_target_{node_offset:08X}");
                block_notes.push(SelectBlockNote::MissingTarget {
                    placeholder: placeholder.clone(),
                });
                (placeholder, Confidence::Inferred)
            }
        };

        blocks.push(SelectBlock {
            target,
            notes: block_notes,
            ops: block_ops,
            trace,
            confidence,
        });
    }

    blocks
}
