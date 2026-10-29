//! Region-based virtual block device composition.
//! Inspired by the regions pattern in nbdkit's floppy plugin (BSD-3-Clause).

use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum RegionType {
    Data(Arc<Vec<u8>>),
    FilePath { path: PathBuf },
    Zero,
}

#[derive(Debug, Clone)]
pub struct Region {
    pub start: u64,
    pub len: u64,
    pub region_type: RegionType,
}

impl Region {
    pub fn end(&self) -> u64 {
        self.start + self.len
    }
}

pub fn find_region(regions: &[Region], offset: u64) -> Option<&Region> {
    regions
        .binary_search_by(|r| {
            if offset < r.start {
                std::cmp::Ordering::Greater
            } else if offset >= r.end() {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
        .map(|i| &regions[i])
}

const PRELOAD_THRESHOLD: u64 = 4096;
const MERGE_CHUNK_MAX: u64 = 4 * 1024 * 1024;

/// Merge runs of small regions into in-memory data regions, reading small
/// files (up to [`PRELOAD_THRESHOLD`]) into memory on the way.
///
/// Fails if one of those files can't be read in full, rather than serving
/// it as zeroes.
pub fn consolidate_regions(regions: Vec<Region>) -> std::io::Result<Vec<Region>> {
    let mut out: Vec<Region> = Vec::new();
    let mut merge_buf: Vec<u8> = Vec::new();
    let mut merge_start: u64 = 0;

    for r in regions {
        let should_inline = match &r.region_type {
            RegionType::FilePath { .. } => r.len <= PRELOAD_THRESHOLD,
            RegionType::Data(_) | RegionType::Zero => true,
        };

        if should_inline {
            if merge_buf.is_empty() {
                merge_start = r.start;
            }
            let needed = (r.start + r.len - merge_start) as usize;
            if needed as u64 > MERGE_CHUNK_MAX && !merge_buf.is_empty() {
                out.push(Region {
                    start: merge_start,
                    len: merge_buf.len() as u64,
                    region_type: RegionType::Data(Arc::new(merge_buf.clone())),
                });
                merge_buf.clear();
                merge_start = r.start;
            }
            let offset_in_buf = (r.start - merge_start) as usize;
            if merge_buf.len() < offset_in_buf + r.len as usize {
                merge_buf.resize(offset_in_buf + r.len as usize, 0);
            }
            match &r.region_type {
                RegionType::Data(data) => {
                    merge_buf[offset_in_buf..offset_in_buf + r.len as usize]
                        .copy_from_slice(&data[..r.len as usize]);
                }
                RegionType::FilePath { path } => {
                    use std::os::unix::fs::FileExt;
                    std::fs::File::open(path)
                        .and_then(|file| {
                            file.read_exact_at(
                                &mut merge_buf[offset_in_buf..offset_in_buf + r.len as usize],
                                0,
                            )
                        })
                        .map_err(|e| {
                            std::io::Error::new(
                                e.kind(),
                                format!("reading {}: {e}", path.display()),
                            )
                        })?;
                }
                RegionType::Zero => {
                    merge_buf[offset_in_buf..offset_in_buf + r.len as usize].fill(0);
                }
            }
        } else {
            if !merge_buf.is_empty() {
                out.push(Region {
                    start: merge_start,
                    len: merge_buf.len() as u64,
                    region_type: RegionType::Data(Arc::new(std::mem::take(&mut merge_buf))),
                });
            }
            out.push(r);
        }
    }
    if !merge_buf.is_empty() {
        out.push(Region {
            start: merge_start,
            len: merge_buf.len() as u64,
            region_type: RegionType::Data(Arc::new(merge_buf)),
        });
    }
    Ok(out)
}

pub fn pread(regions: &[Region], buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    let mut remaining = buf.len();
    let mut buf_offset = 0;
    let mut disk_offset = offset;

    while remaining > 0 {
        let region = find_region(regions, disk_offset).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("offset {} outside disk", disk_offset),
            )
        })?;

        let region_offset = disk_offset - region.start;
        let avail = (region.len - region_offset) as usize;
        let len = remaining.min(avail);

        match &region.region_type {
            RegionType::Data(data) => {
                let start = region_offset as usize;
                buf[buf_offset..buf_offset + len].copy_from_slice(&data[start..start + len]);
            }
            RegionType::FilePath { path } => {
                use std::os::unix::fs::FileExt;
                let file = std::fs::File::open(path)?;
                file.read_exact_at(&mut buf[buf_offset..buf_offset + len], region_offset)?;
            }
            RegionType::Zero => {
                buf[buf_offset..buf_offset + len].fill(0);
            }
        }

        remaining -= len;
        buf_offset += len;
        disk_offset += len as u64;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_region(start: u64, len: u64, path: PathBuf) -> Region {
        Region {
            start,
            len,
            region_type: RegionType::FilePath { path },
        }
    }

    #[test]
    fn test_consolidate_preloads_small_files() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("small");
        std::fs::write(&small, b"hello").unwrap();
        let regions = consolidate_regions(vec![file_region(0, 5, small)]).unwrap();
        assert_eq!(regions.len(), 1);
        let mut buf = [0u8; 5];
        pread(&regions, &mut buf, 0).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_consolidate_fails_on_unreadable_small_file() {
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short");
        std::fs::write(&short, b"abc").unwrap();
        for (path, len) in [(dir.path().join("missing"), 3), (short, 10)] {
            let err = consolidate_regions(vec![file_region(0, len, path.clone())]).unwrap_err();
            assert!(
                err.to_string().contains(&path.display().to_string()),
                "{err}"
            );
        }
    }
}
