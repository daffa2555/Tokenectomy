use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub enum BoundaryError {
    PathEscapesBoundary {
        path: PathBuf,
        root: PathBuf,
    },
    ForbiddenSequence(String),
    NotFound(PathBuf),
    Io(std::io::Error),
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundaryError::PathEscapesBoundary { path, root } => {
                write!(f, "Path '{}' escapes workspace root '{}'", path.display(), root.display())
            }
            BoundaryError::ForbiddenSequence(seq) => {
                write!(f, "Forbidden path sequence: {}", seq)
            }
            BoundaryError::NotFound(p) => {
                write!(f, "Target path '{}' does not exist", p.display())
            }
            BoundaryError::Io(err) => {
                write!(f, "Filesystem I/O error: {}", err)
            }
        }
    }
}

impl std::error::Error for BoundaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BoundaryError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BoundaryError {
    fn from(err: std::io::Error) -> Self {
        BoundaryError::Io(err)
    }
}

/// Unified security boundary for all filesystem access across Tokenectomy.
/// Guarantees:
/// 1. Canonicalization: symlinks and `..` components resolved to physical paths.
/// 2. Bounded access: all operations are strictly constrained within the workspace root.
/// 3. Traversal immunity: blocks null bytes, parent directory escapes, and root deviations.
#[derive(Debug, Clone)]
pub struct WorkspaceBoundary {
    root: PathBuf,
}

impl WorkspaceBoundary {
    /// Creates a new workspace boundary anchored at `root`.
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, BoundaryError> {
        let p = root.as_ref();
        let canonical = p.canonicalize()?;
        Ok(Self { root: canonical })
    }

    /// Initializes a boundary using the current working directory (CWD).
    pub fn current() -> Result<Self, BoundaryError> {
        let cwd = std::env::current_dir()?;
        Self::new(cwd)
    }

    /// Returns the canonical workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves and validates that `path` stays strictly within the workspace boundary.
    pub fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, BoundaryError> {
        let p = path.as_ref();
        let p_str = p.to_string_lossy();

        if p_str.contains('\0') {
            return Err(BoundaryError::ForbiddenSequence("Path contains null byte".into()));
        }

        let abs_path = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.root.join(p)
        };

        if abs_path.exists() {
            let canonical = abs_path.canonicalize()?;
            if canonical.starts_with(&self.root) {
                Ok(canonical)
            } else {
                Err(BoundaryError::PathEscapesBoundary {
                    path: canonical,
                    root: self.root.clone(),
                })
            }
        } else {
            // For files that do not exist yet (e.g. pending write):
            // Find the deepest existing ancestor and verify it resides in root
            let mut ancestor = abs_path.as_path();
            while !ancestor.exists() {
                match ancestor.parent() {
                    Some(parent) => ancestor = parent,
                    None => break,
                }
            }

            let canonical_ancestor = if ancestor.exists() {
                ancestor.canonicalize()?
            } else {
                self.root.clone()
            };

            if !canonical_ancestor.starts_with(&self.root) {
                return Err(BoundaryError::PathEscapesBoundary {
                    path: abs_path,
                    root: self.root.clone(),
                });
            }

            // Ensure relative components do not escape
            let mut depth: isize = 0;
            for comp in p.components() {
                match comp {
                    Component::ParentDir => {
                        depth -= 1;
                        if depth < 0 && !p.is_absolute() {
                            return Err(BoundaryError::PathEscapesBoundary {
                                path: abs_path,
                                root: self.root.clone(),
                            });
                        }
                    }
                    Component::Normal(_) => {
                        depth += 1;
                    }
                    _ => {}
                }
            }

            Ok(abs_path)
        }
    }

    /// Validates whether a path is safe within this boundary.
    pub fn is_safe<P: AsRef<Path>>(&self, path: P) -> bool {
        self.resolve(path).is_ok()
    }

    /// Reads a file safely within the workspace boundary.
    pub fn read<P: AsRef<Path>>(&self, path: P) -> Result<String, BoundaryError> {
        let safe_path = self.resolve(path)?;
        if !safe_path.is_file() {
            return Err(BoundaryError::NotFound(safe_path));
        }
        let meta = fs::metadata(&safe_path)?;
        if meta.len() > 10 * 1024 * 1024 {
            return Err(BoundaryError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("File '{}' exceeds 10MB size limit ({} bytes)", safe_path.display(), meta.len()),
            )));
        }
        let content = fs::read_to_string(&safe_path)?;
        Ok(content)
    }

    /// Writes data safely to a file within the workspace boundary using atomic write-and-rename.
    /// Ensures parent directories exist and guarantees zero corrupt diff on process crash.
    pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(&self, path: P, content: C) -> Result<(), BoundaryError> {
        static WRITE_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let safe_path = self.resolve(path)?;
        let parent = safe_path.parent().unwrap_or(&self.root);
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
        let file_name = safe_path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp");
        let counter = WRITE_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_path = parent.join(format!(".{}.tmp.{}_{}", file_name, std::process::id(), counter));
        fs::write(&tmp_path, content)?;
        fs::rename(&tmp_path, &safe_path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_current_dir() {
        let boundary = WorkspaceBoundary::current().expect("current dir boundary");
        assert!(boundary.root().exists());

        // Relative file inside CWD
        assert!(boundary.is_safe("Cargo.toml"));
        let resolved = boundary.resolve("Cargo.toml").expect("resolve Cargo.toml");
        assert!(resolved.ends_with("Cargo.toml"));
    }

    #[test]
    fn test_boundary_blocks_traversal_escape() {
        let boundary = WorkspaceBoundary::current().expect("current dir boundary");

        // Attempt traversal out of root
        assert!(!boundary.is_safe("../../../../etc/passwd"));
        assert!(!boundary.is_safe("/etc/passwd"));
        assert!(!boundary.is_safe("foo/../../../../../../etc/shadow"));
    }

    #[test]
    fn test_boundary_blocks_null_byte() {
        let boundary = WorkspaceBoundary::current().expect("current dir boundary");
        assert!(!boundary.is_safe("Cargo.toml\0hidden"));
    }

    #[test]
    fn test_boundary_read_valid_file() {
        let boundary = WorkspaceBoundary::current().expect("current dir boundary");
        let content = boundary.read("Cargo.toml").expect("read Cargo.toml");
        assert!(content.contains("[package]"));
    }
}
