use crate::dir_walk::{ChildRef, DirInfo, WalkResult};
use crate::regions::{Region, RegionType};
use std::sync::Arc;

const EROFS_MAGIC: u32 = 0xE0F5E1E2;
const BLOCK_SIZE: u64 = 4096;
const BLOCK_BITS: u8 = 12;
const SUPERBLOCK_OFFSET: u64 = 1024;

// EROFS inode formats
const EROFS_INODE_LAYOUT_EXTENDED: u16 = 1;

/// Size of an extended inode. Compact (32 byte) ones would be smaller,
/// but hold only 32-bit sizes, 16-bit UIDs, GIDs and link counts, and no
/// mtime; every inode is extended, so none of those get truncated.
const INODE_SIZE: u64 = 64;
/// Inode numbers (nids) count 32-byte slots from the inode table start.
const INODE_SLOT_SIZE: u64 = 32;

/// The nid of the inode at `inode_id` in the inode table.
fn nid(inode_id: u64) -> u64 {
    inode_id * (INODE_SIZE / INODE_SLOT_SIZE)
}

/// Byte offset of the inode at `inode_id`, given where the table starts.
fn inode_offset(table_offset: u64, inode_id: u64) -> usize {
    (table_offset + inode_id * INODE_SIZE) as usize
}

// EROFS data layouts
const EROFS_INODE_FLAT_PLAIN: u16 = 0;

// EROFS file types (matching Linux DT_* values)
const EROFS_FT_REG_FILE: u8 = 1;
const EROFS_FT_DIR: u8 = 2;
const EROFS_FT_SYMLINK: u8 = 7;

#[derive(Debug)]
pub struct FileRegion {
    pub file_index: usize,
    pub offset_in_erofs: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct ErofsLayout {
    pub metadata: Vec<u8>,
    pub file_regions: Vec<FileRegion>,
    pub total_size: u64,
}

struct DirEntryOnDisk {
    nid: u64,
    file_type: u8,
    name: Vec<u8>,
}

pub fn build_erofs(walk: &WalkResult) -> std::io::Result<ErofsLayout> {
    let total_inodes = walk.dirs.len() + walk.files.len() + walk.symlinks.len();

    // Phase 1: Assign inode positions
    // Inodes start at block 1 (block 0 has superblock)
    let inode_table_offset = BLOCK_SIZE; // block 1
    let inode_table_size = align_up(total_inodes as u64 * INODE_SIZE, BLOCK_SIZE);

    // Phase 2: Build directory entry blocks
    let dir_blocks_offset = inode_table_offset + inode_table_size;
    let mut dir_data: Vec<u8> = Vec::new();
    let mut dir_block_offsets: Vec<u64> = Vec::new(); // per-directory offset in dir_data
    let mut dir_sizes: Vec<u64> = Vec::new();

    for dir in &walk.dirs {
        let offset = align_up(dir_data.len() as u64, BLOCK_SIZE);
        dir_data.resize(offset as usize, 0);
        dir_block_offsets.push(dir_blocks_offset + offset);

        let start = dir_data.len();
        // Write EROFS directory blocks (splits at 4096-byte boundaries)
        write_dir_blocks(&mut dir_data, &dir_entries(dir, walk));
        // Only the last block isn't padded to the block size
        dir_sizes.push((dir_data.len() - start) as u64);
    }
    let dir_data_size = align_up(dir_data.len() as u64, BLOCK_SIZE);
    dir_data.resize(dir_data_size as usize, 0);

    // Phase 3: Compute data region layout
    let data_offset = dir_blocks_offset + dir_data_size;
    let mut file_regions = Vec::new();
    let mut current_data_offset = data_offset;

    for (i, file) in walk.files.iter().enumerate() {
        if file.size > 0 {
            let aligned_offset = align_up(current_data_offset, BLOCK_SIZE);
            file_regions.push(FileRegion {
                file_index: i,
                offset_in_erofs: aligned_offset,
                size: file.size,
            });
            current_data_offset = aligned_offset + align_up(file.size, BLOCK_SIZE);
        }
    }

    // Symlink targets also need data blocks
    for (si, symlink) in walk.symlinks.iter().enumerate() {
        if !symlink.target.is_empty() {
            let aligned_offset = align_up(current_data_offset, BLOCK_SIZE);
            file_regions.push(FileRegion {
                file_index: walk.files.len() + si, // files.len() + symlink index
                offset_in_erofs: aligned_offset,
                size: symlink.target.len() as u64,
            });
            current_data_offset =
                aligned_offset + align_up(symlink.target.len() as u64, BLOCK_SIZE);
        }
    }

    let total_size = align_up(current_data_offset, BLOCK_SIZE);
    let total_blocks = total_size / BLOCK_SIZE;

    // Phase 4: Build metadata blob
    let mut metadata = vec![0u8; (dir_blocks_offset + dir_data_size) as usize];

    // Write superblock at offset 1024
    write_superblock(
        &mut metadata,
        total_inodes as u32,
        total_blocks as u32,
        0, // root nid
    );

    // Write inodes
    // Directories
    for (i, dir) in walk.dirs.iter().enumerate() {
        let dir_size = dir_sizes[i];
        let dir_block = (dir_block_offsets[i] - dir_blocks_offset) / BLOCK_SIZE;
        write_inode(
            &mut metadata,
            inode_offset(inode_table_offset, dir.inode_id),
            0o040000 | (dir.mode & 0o7777),
            dir.uid,
            dir.gid,
            dir_size,
            dir.mtime,
            2 + dir
                .children
                .iter()
                .filter(|c| matches!(c, ChildRef::Dir(_)))
                .count() as u32,
            EROFS_INODE_FLAT_PLAIN,
            (dir_blocks_offset / BLOCK_SIZE + dir_block) as u32,
        );
    }

    // Regular files
    for (i, file) in walk.files.iter().enumerate() {
        let data_block = if file.size > 0 {
            let fr = file_regions.iter().find(|r| r.file_index == i);
            fr.map(|r| (r.offset_in_erofs / BLOCK_SIZE) as u32)
                .unwrap_or(0)
        } else {
            0
        };
        write_inode(
            &mut metadata,
            inode_offset(inode_table_offset, file.inode_id),
            0o100000 | (file.mode & 0o7777),
            file.uid,
            file.gid,
            file.size,
            file.mtime,
            file.nlink,
            EROFS_INODE_FLAT_PLAIN,
            data_block,
        );
    }

    // Symlinks: FlatPlain with target in data region
    // File regions for symlinks start after file regions
    let file_region_count = walk.files.iter().filter(|f| f.size > 0).count();
    let mut sym_fr_idx = file_region_count;
    for symlink in &walk.symlinks {
        let data_block = if !symlink.target.is_empty() {
            let fr = &file_regions[sym_fr_idx];
            sym_fr_idx += 1;
            (fr.offset_in_erofs / BLOCK_SIZE) as u32
        } else {
            0
        };

        write_inode(
            &mut metadata,
            inode_offset(inode_table_offset, symlink.inode_id),
            0o120000 | (symlink.mode & 0o7777),
            symlink.uid,
            symlink.gid,
            symlink.target.len() as u64,
            symlink.mtime,
            1,
            EROFS_INODE_FLAT_PLAIN,
            data_block,
        );
    }

    // Write directory data
    let dir_start = dir_blocks_offset as usize;
    if dir_start + dir_data.len() <= metadata.len() {
        metadata[dir_start..dir_start + dir_data.len()].copy_from_slice(&dir_data);
    }

    Ok(ErofsLayout {
        metadata,
        file_regions,
        total_size,
    })
}

fn write_superblock(buf: &mut [u8], inodes: u32, blocks: u32, root_nid: u16) {
    let off = SUPERBLOCK_OFFSET as usize;
    // magic
    buf[off..off + 4].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
    // checksum (unused)
    // feature_compat
    buf[off + 8..off + 12].copy_from_slice(&0u32.to_le_bytes());
    // blkszbits
    buf[off + 12] = BLOCK_BITS;
    // sb_extslots
    buf[off + 13] = 0;
    // root_nid
    buf[off + 14..off + 16].copy_from_slice(&root_nid.to_le_bytes());
    // inos
    buf[off + 16..off + 24].copy_from_slice(&(inodes as u64).to_le_bytes());
    // build_time
    buf[off + 24..off + 32].copy_from_slice(&0u64.to_le_bytes());
    // build_time_nsec
    buf[off + 32..off + 36].copy_from_slice(&0u32.to_le_bytes());
    // blocks
    buf[off + 36..off + 40].copy_from_slice(&blocks.to_le_bytes());
    // meta_blkaddr (inode table starts at block 1)
    buf[off + 40..off + 44].copy_from_slice(&1u32.to_le_bytes());
    // xattr_blkaddr
    buf[off + 44..off + 48].copy_from_slice(&0u32.to_le_bytes());
    // uuid (16 bytes)
    // volume_name (16 bytes)
    // feature_incompat
    buf[off + 80..off + 84].copy_from_slice(&0u32.to_le_bytes());
    // available_compr_algs (union with checksum)
    // lz4_max_distance
}

/// Write an extended inode (`struct erofs_inode_extended`).
fn write_inode(
    buf: &mut [u8],
    offset: usize,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: u64,
    nlink: u32,
    data_layout: u16,
    u_field: u32,
) {
    let inode = &mut buf[offset..offset + INODE_SIZE as usize];
    // format: layout | data_layout << 1
    let format = EROFS_INODE_LAYOUT_EXTENDED | (data_layout << 1);
    inode[0..2].copy_from_slice(&format.to_le_bytes());
    // xattr_icount
    inode[2..4].copy_from_slice(&0u16.to_le_bytes());
    // mode (file type and permissions fit in 16 bits)
    inode[4..6].copy_from_slice(&(mode as u16).to_le_bytes());
    // reserved
    inode[6..8].copy_from_slice(&0u16.to_le_bytes());
    inode[8..16].copy_from_slice(&size.to_le_bytes());
    // u (union: raw_blkaddr for FlatPlain)
    inode[16..20].copy_from_slice(&u_field.to_le_bytes());
    // ino (only for 32-bit stat compatibility)
    inode[20..24].copy_from_slice(&0u32.to_le_bytes());
    inode[24..28].copy_from_slice(&uid.to_le_bytes());
    inode[28..32].copy_from_slice(&gid.to_le_bytes());
    inode[32..40].copy_from_slice(&mtime.to_le_bytes());
    // mtime_nsec
    inode[40..44].copy_from_slice(&0u32.to_le_bytes());
    inode[44..48].copy_from_slice(&nlink.to_le_bytes());
    // reserved2
    inode[48..64].fill(0);
}

fn write_dir_blocks(buf: &mut Vec<u8>, entries: &[DirEntryOnDisk]) {
    // EROFS directories are split into 4096-byte blocks.
    // Each block contains: [headers...][names...]
    // header = 12 bytes: nid(8) + nameoff(2) + file_type(1) + reserved(1)
    // nameoff is relative to block start.

    let mut remaining = entries;

    while !remaining.is_empty() {
        // Determine how many entries fit in this block
        let mut count = 0;
        let mut total_size: usize = 0;
        for entry in remaining {
            let entry_size = 12 + entry.name.len();
            if total_size + entry_size > BLOCK_SIZE as usize && count > 0 {
                break;
            }
            total_size += entry_size;
            count += 1;
        }

        let block_entries = &remaining[..count];
        remaining = &remaining[count..];

        // Write headers
        let header_total = 12 * block_entries.len();
        let mut nameoff = header_total as u16;
        for entry in block_entries {
            buf.extend_from_slice(&(entry.nid as u64).to_le_bytes());
            buf.extend_from_slice(&nameoff.to_le_bytes());
            buf.push(entry.file_type);
            buf.push(0);
            nameoff += entry.name.len() as u16;
        }

        // Write names
        for entry in block_entries {
            buf.extend_from_slice(&entry.name);
        }

        // Pad to block boundary (except last block which is sized by inode.size)
        if !remaining.is_empty() {
            let written = total_size;
            let pad = BLOCK_SIZE as usize - (written % BLOCK_SIZE as usize);
            if pad < BLOCK_SIZE as usize {
                buf.resize(buf.len() + pad, 0);
            }
        }
    }
}

/// The entries of a directory, "." and ".." included, sorted by name as
/// mkfs.erofs sorts them: the kernel finds a name by binary search, so
/// names sorting before "." (such as "-config") have to come first.
fn dir_entries(dir: &DirInfo, walk: &WalkResult) -> Vec<DirEntryOnDisk> {
    let dot = |name: &[u8], inode_id| DirEntryOnDisk {
        nid: nid(inode_id),
        file_type: EROFS_FT_DIR,
        name: name.to_vec(),
    };
    // The root's parent is itself
    let mut entries = vec![dot(b".", dir.inode_id), dot(b"..", dir.parent_inode_id)];
    entries.extend(dir.children.iter().map(|child| match child {
        ChildRef::Dir(di) => {
            let child_dir = &walk.dirs[*di];
            DirEntryOnDisk {
                nid: nid(child_dir.inode_id),
                file_type: EROFS_FT_DIR,
                name: child_dir.name.as_encoded_bytes().to_vec(),
            }
        }
        ChildRef::File(fi) => {
            let file = &walk.files[*fi];
            DirEntryOnDisk {
                nid: nid(file.inode_id),
                file_type: EROFS_FT_REG_FILE,
                name: file
                    .host_path
                    .file_name()
                    .unwrap_or_default()
                    .as_encoded_bytes()
                    .to_vec(),
            }
        }
        ChildRef::Symlink(si) => {
            let symlink = &walk.symlinks[*si];
            DirEntryOnDisk {
                nid: nid(symlink.inode_id),
                file_type: EROFS_FT_SYMLINK,
                name: symlink.name.clone(),
            }
        }
    }));
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}

pub fn build_erofs_regions(layout: &ErofsLayout, walk: &WalkResult) -> Vec<Region> {
    let files = &walk.files;
    let mut regions = Vec::new();

    // Metadata region (superblock + inode table + dir blocks)
    regions.push(Region {
        start: 0,
        len: layout.metadata.len() as u64,
        region_type: RegionType::Data(Arc::new(layout.metadata.clone())),
    });

    // File and symlink data regions
    for fr in &layout.file_regions {
        // Padding gap
        let current_end = regions.last().map(|r| r.start + r.len).unwrap_or(0);
        if fr.offset_in_erofs > current_end {
            regions.push(Region {
                start: current_end,
                len: fr.offset_in_erofs - current_end,
                region_type: RegionType::Zero,
            });
        }

        if fr.file_index < files.len() {
            // Regular file: read from host
            regions.push(Region {
                start: fr.offset_in_erofs,
                len: fr.size,
                region_type: RegionType::FilePath {
                    path: files[fr.file_index].host_path.clone(),
                },
            });
        } else {
            // Symlink target: inline data
            let sym_idx = fr.file_index - files.len();
            if sym_idx < walk.symlinks.len() {
                // Pad symlink target to fill the block
                let mut data = walk.symlinks[sym_idx].target.clone();
                data.resize(fr.size as usize, 0);
                regions.push(Region {
                    start: fr.offset_in_erofs,
                    len: fr.size,
                    region_type: RegionType::Data(Arc::new(data)),
                });
            }
        }

        // Padding to block boundary
        let end = fr.offset_in_erofs + fr.size;
        let aligned_end = align_up(end, BLOCK_SIZE);
        if aligned_end > end {
            regions.push(Region {
                start: end,
                len: aligned_end - end,
                region_type: RegionType::Zero,
            });
        }
    }

    // Ensure total size
    let last_end = regions.last().map(|r| r.start + r.len).unwrap_or(0);
    if last_end < layout.total_size {
        regions.push(Region {
            start: last_end,
            len: layout.total_size - last_end,
            region_type: RegionType::Zero,
        });
    }

    regions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dir_walk::FileEntry;

    fn le_u16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
    }
    fn le_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn le_u64(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    /// Values that don't fit a compact inode come out unchanged.
    #[test]
    fn test_extended_inodes() {
        const SIZE: u64 = 5 << 30;
        const UID: u32 = 100_000;
        const GID: u32 = 100_001;
        const MTIME: u64 = 1 << 33;
        let walk = WalkResult {
            dirs: vec![DirInfo {
                name: Default::default(),
                mode: 0o040755,
                uid: UID,
                gid: GID,
                mtime: MTIME,
                inode_id: 0,
                parent_inode_id: 0,
                children: vec![ChildRef::File(0)],
            }],
            files: vec![FileEntry {
                host_path: "/img/big".into(),
                size: SIZE,
                mode: 0o100644,
                uid: UID,
                gid: GID,
                mtime: MTIME,
                nlink: 70_000,
                inode_id: 1,
            }],
            symlinks: vec![],
        };
        let layout = build_erofs(&walk).unwrap();
        let md = &layout.metadata;
        let sb = SUPERBLOCK_OFFSET as usize;
        assert_eq!(le_u32(md, sb), EROFS_MAGIC);
        let meta_blkaddr = le_u32(md, sb + 40) as usize;

        // The root directory's entry for the file points at nid 2, the
        // second 64-byte inode
        let root = meta_blkaddr * BLOCK_SIZE as usize;
        assert_eq!(le_u16(md, root) & 1, EROFS_INODE_LAYOUT_EXTENDED);
        let dir_block = le_u32(md, root + 16) as usize * BLOCK_SIZE as usize;
        // ".", "..", then "big"
        assert_eq!(le_u64(md, dir_block + 2 * 12), 2);

        let inode = root + 2 * INODE_SLOT_SIZE as usize;
        assert_eq!(le_u16(md, inode) & 1, EROFS_INODE_LAYOUT_EXTENDED);
        assert_eq!(le_u16(md, inode + 4), 0o100644);
        assert_eq!(le_u64(md, inode + 8), SIZE);
        assert_eq!(le_u32(md, inode + 24), UID);
        assert_eq!(le_u32(md, inode + 28), GID);
        assert_eq!(le_u64(md, inode + 32), MTIME);
        assert_eq!(le_u32(md, inode + 44), 70_000);
        assert_eq!(layout.file_regions[0].size, SIZE);
    }

    /// Directory entries are sorted by name, "." and ".." included, in
    /// each block and across blocks, and the directory's size spans them.
    #[test]
    fn test_dir_entries_sorted() {
        // Some sort before ".", one after every letter
        let mut names: Vec<String> = ["+x", "-config", "a", "~"].map(String::from).into();
        // Enough to fill more than one block
        names.extend((0..400).map(|i| format!("file-{i:04}")));
        let walk = WalkResult {
            dirs: vec![DirInfo {
                name: Default::default(),
                mode: 0o040755,
                uid: 0,
                gid: 0,
                mtime: 0,
                inode_id: 0,
                parent_inode_id: 0,
                children: (0..names.len()).map(ChildRef::File).collect(),
            }],
            files: names
                .iter()
                .enumerate()
                .map(|(i, name)| FileEntry {
                    host_path: format!("/img/{name}").into(),
                    size: 0,
                    mode: 0o100644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    nlink: 1,
                    inode_id: i as u64 + 1,
                })
                .collect(),
            symlinks: vec![],
        };
        let layout = build_erofs(&walk).unwrap();
        let md = &layout.metadata;
        let root = BLOCK_SIZE as usize;
        let size = le_u64(md, root + 8) as usize;
        let start = le_u32(md, root + 16) as usize * BLOCK_SIZE as usize;
        assert!(size > BLOCK_SIZE as usize, "{size}");

        let mut found: Vec<&[u8]> = Vec::new();
        for block_start in (0..size).step_by(BLOCK_SIZE as usize) {
            let block =
                &md[start + block_start..start + size.min(block_start + BLOCK_SIZE as usize)];
            // The first name follows the last 12-byte header
            let count = le_u16(block, 8) as usize / 12;
            let mut ends: Vec<usize> = (1..count)
                .map(|i| le_u16(block, i * 12 + 8) as usize)
                .collect();
            ends.push(block.len());
            let mut name_start = le_u16(block, 8) as usize;
            for end in ends {
                // The last name in a block is padded with NULs
                let name = block[name_start..end].split(|&b| b == 0).next().unwrap();
                found.push(name);
                name_start = end;
            }
        }
        assert_eq!(found.len(), names.len() + 2);
        assert!(found.windows(2).all(|w| w[0] < w[1]), "{found:?}");
        let mut expected: Vec<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
        expected.extend([&b"."[..], b".."]);
        expected.sort();
        assert_eq!(found, expected);
        assert_eq!(expected[..4], [&b"+x"[..], b"-config", b".", b".."]);
    }
}
