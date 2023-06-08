use std::{
    collections::HashMap,
    fs::{self, read_dir},
    io::{BufWriter, StdoutLock, Write},
    path::Path,
};

const TODO: &str = "TODO";
const NOTE: &str = "NOTE";
const FIXME: &str = "FIXME";
const BUG: &str = "BUG";
const HACK: &str = "HACK";
const XXX: &str = "XXX";
const OPTIMIZE: &str = "OPTIMIZE";

static mut FILE_COUNTER: usize = 0;
static mut LINE_COUNTER: usize = 0;

#[derive(Clone)]
struct SpecialPattern {
    pub name: &'static str,
    pub pref: &'static str,
    pub post: &'static str,
}

impl SpecialPattern {
    pub fn new(name: &'static str, pref: &'static str, post: &'static str) -> Self {
        Self { name, pref, post }
    }
}

#[derive(Clone)]
struct CommentPattern {
    pub pref: &'static str,
    pub post: &'static str,
}

impl CommentPattern {
    pub fn new(pref: &'static str, post: &'static str) -> Self {
        Self { pref, post }
    }
}

#[derive(Clone)]
struct Patterns {
    pub comments: Vec<CommentPattern>,
    pub special: Vec<SpecialPattern>,
}

impl Patterns {
    pub fn new() -> Self {
        Self {
            comments: Vec::new(),
            special: Vec::new(),
        }
    }
}

type LangPatterns = HashMap<&'static str, Patterns>;

fn build_patterns() -> LangPatterns {
    let mut rust_patterns = Patterns::new();
    rust_patterns.comments.push(CommentPattern::new("//", "\n"));
    rust_patterns.comments.push(CommentPattern::new("/*", "*/"));
    rust_patterns
        .special
        .push(SpecialPattern::new("TODO!", "todo!(\"", "\""));

    let mut python_patterns = Patterns::new();
    python_patterns
        .comments
        .push(CommentPattern::new("#", "\n"));

    let mut c_patterns = Patterns::new();
    c_patterns.comments.push(CommentPattern::new("//", "\n"));
    c_patterns.comments.push(CommentPattern::new("/*", "*/"));

    let mut zig_patterns = Patterns::new();
    zig_patterns.comments.push(CommentPattern::new("//", "\n"));

    LangPatterns::from([
        ("zig", zig_patterns),
        ("rs", rust_patterns),
        ("py", python_patterns),
        ("c", c_patterns.clone()),
        ("cpp", c_patterns),
    ])
}

fn format_msg(tag: &str, message: &str, line: usize) -> String {
    let cleaned_message = message.trim_matches(&[' ', ':'][..]);
    format!("-- [{line}] {tag} '{cleaned_message}'")
}

fn format_comment(comment: &str, line: usize) -> Option<String> {
    Some(match comment {
        c if c.contains(TODO) => format_msg(TODO, c.split_once(TODO).unwrap().1, line),
        c if c.contains(NOTE) => format_msg(NOTE, c.split_once(NOTE).unwrap().1, line),
        c if c.contains(BUG) => format_msg(BUG, c.split_once(BUG).unwrap().1, line),
        c if c.contains(FIXME) => format_msg(FIXME, c.split_once(FIXME).unwrap().1, line),
        c if c.contains(HACK) => format_msg(HACK, c.split_once(HACK).unwrap().1, line),
        c if c.contains(OPTIMIZE) => format_msg(OPTIMIZE, c.split_once(OPTIMIZE).unwrap().1, line),
        c if c.contains(XXX) => format_msg(XXX, c.split_once(XXX).unwrap().1, line),
        _ => return None,
    })
}

fn handle_file(path: &Path, patterns: &LangPatterns, writer: &mut BufWriter<StdoutLock>) {
    let ext_patterns = if let Some(ext) = path.extension() {
        if let Some(fp) = patterns.get(ext.to_string_lossy().as_ref()) {
            fp
        } else {
            return;
        }
    } else {
        return;
    };

    let file_str = match fs::read_to_string(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("warning: can't read file {:?}.\n  details: {}", path, err);
            return;
        }
    };

    let mut line: usize = 1;
    let mut char_iter = file_str.chars();
    let mut printed = false;

    while let Some(c) = char_iter.next() {
        if c == '\n' {
            unsafe { LINE_COUNTER += 1 };
            line += 1;
            continue;
        }

        let start_tail = char_iter.as_str();

        let mut handled = false;
        for CommentPattern { pref, post } in &ext_patterns.comments {
            if pref.chars().next() != Some(c) {
                continue;
            }
            let matches = (pref.len() - 1 <= char_iter.as_str().len())
                && (&char_iter.as_str().as_bytes()[0..pref.len() - 1] == pref[1..].as_bytes());

            if matches {
                for _ in 1..pref.len() {
                    char_iter.next();
                }

                let comment_tail = char_iter.as_str();
                let comment_tail_len = comment_tail.len();
                let mut end_tail_len = comment_tail_len;

                while let Some(c) = char_iter.next() {
                    if post.chars().next() == Some(c) {
                        let matches = (post.len() - 1 <= char_iter.as_str().len())
                            && (&char_iter.as_str().as_bytes()[0..post.len() - 1]
                                == post[1..].as_bytes());
                        if matches {
                            end_tail_len = char_iter.as_str().len() + 1;

                            for _ in 1..post.len() {
                                char_iter.next();
                            }

                            break;
                        }
                    }
                }

                let comment_len = comment_tail_len - end_tail_len;
                let comment_slice = comment_tail[0..comment_len].trim();

                handled = true;

                if let Some(formatted) = format_comment(comment_slice, line) {
                    if !printed {
                        printed = true;
                        writeln!(writer, "\n{}", path.to_str().unwrap_or("undefined:")).unwrap();
                    }
                    writeln!(writer, "{formatted}").unwrap();
                }
            }
        }

        if !handled {
            for SpecialPattern { name, pref, post } in &ext_patterns.special {
                if post.chars().next() == Some(c) {
                    continue;
                }

                let matches = (pref.len() - 1 <= char_iter.as_str().len())
                    && (&char_iter.as_str().as_bytes()[0..pref.len() - 1] == pref[1..].as_bytes());
                if matches {
                    for _ in 1..pref.len() {
                        char_iter.next();
                    }

                    let comment_tail = char_iter.as_str();
                    let comment_tail_len = comment_tail.len();
                    let mut end_tail_len = comment_tail_len;

                    while let Some(c) = char_iter.next() {
                        if post.chars().next() == Some(c) {
                            let matches = (post.len() - 1 <= char_iter.as_str().len())
                                && (&char_iter.as_str().as_bytes()[0..post.len() - 1]
                                    == post[1..].as_bytes());

                            if matches {
                                end_tail_len = char_iter.as_str().len() + 1;

                                for _ in 1..post.len() {
                                    char_iter.next();
                                }

                                break;
                            }
                        }
                    }

                    let comment_len = comment_tail_len - end_tail_len;
                    let comment_slice = &comment_tail[0..comment_len].trim_end();

                    if !printed {
                        printed = true;
                        writeln!(writer, "\n{}", path.to_str().unwrap_or("undefined:")).unwrap();
                    }
                    writeln!(writer, "{}", format_msg(name, comment_slice, line)).unwrap();
                }
            }
        }

        let end_tail = char_iter.as_str();
        let slice = &start_tail[0..start_tail.len() - end_tail.len()];
        let lines_offset = slice
            .chars()
            .map(|c| if c == '\n' { 1 } else { 0 })
            .sum::<usize>();

        line += lines_offset;
        unsafe { LINE_COUNTER += lines_offset };
    }
}

fn traverse(path: &Path, patterns: &LangPatterns, writer: &mut BufWriter<StdoutLock>) {
    unsafe {
        FILE_COUNTER += 1;
    }
    let dir_iter_opt = read_dir(path);
    let dir_iter = match dir_iter_opt {
        Ok(entries) => entries,
        _ => {
            eprintln!("warning: can't read directory");
            return;
        }
    };

    for entry_res in dir_iter {
        let entry = match entry_res {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!(
                    "warning: can't read directory entry.\n   details: '{}'",
                    err
                );
                continue;
            }
        };

        let entry_type_res = entry.file_type();
        let entry_type = match entry_type_res {
            Ok(t) => t,
            Err(err) => {
                eprintln!(
                    "warning: can't check directory entry type.\n    details: {}",
                    err
                );
                continue;
            }
        };

        if entry_type.is_file() {
            handle_file(&entry.path(), patterns, writer)
        } else if entry_type.is_dir() {
            traverse(&entry.path(), patterns, writer)
        }
    }
}

fn main() {
    let path = match std::env::args().skip(1).next() {
        Some(dir_path) => dir_path,
        None => "./".to_string(),
    };

    let patterns = build_patterns();
    let mut writer = BufWriter::with_capacity(1024 * 1024, std::io::stdout().lock());
    traverse(Path::new(&path), &patterns, &mut writer);
    writer.flush().unwrap();
    println!("Files processed: {}", unsafe { FILE_COUNTER });
    println!("Lines processed: {}", unsafe { LINE_COUNTER });
}
