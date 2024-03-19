//! Key–value mappings for the representation of client and server options.

use itertools::Itertools;
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use crate::Error;

/// Private pattern used for counting
///
/// This is a way to force the type as slice of ()
/// turns array into slice then calls slice implementation of len
///
/// This is evaluated at compile time so there are no more allocations
/// to run the macro. Unit () is a zero size type.
///
/// (<[()]>)::len(...)    - treat this as a Unit slice and the take the length
///
/// The (@single ...) target pattern allows us to substitute Units for whatever
/// object is in the expr so we can count with a const object that doesn't
/// require an allocation. See
/// [The Little Book of Rust Macros](https://veykril.github.io/tlborm/decl-macros/building-blocks/counting.html)
/// for more detail.
#[doc(hidden)]
macro_rules! count {
    (@single $($x:tt)*) => (());
    (@count $($rest:expr),*) => (<[()]>::len(&[$(count!(@single $rest)),*]));
}

/// Create an **Args** object from a list of key-value pairs
///
/// ## Example
///
/// ```ignore
/// # #[macro_use] extern crate ptrs;
/// # fn main() {
///
/// let map = args!{
///     "a" => 1,
///     "b" => 2,
/// };
/// assert_eq!(map["a"], 1);
/// assert_eq!(map["b"], 2);
/// assert_eq!(map.get("c"), None);
/// # }
/// ```
#[macro_export]
macro_rules! args {
    ($($key:expr => $value:expr,)+) => { args!($($key => $value),+) };
    ($($key:expr => $value:expr),*) => {
        {
            let _cap = count!(@count $($key),*);
            let mut _map = ::std::collections::HashMap::with_capacity(_cap);
            $(
                let _ = _map.insert($key, $value);
            )*
            Args(_map)
        }
    };
}

/// Create a **HashMap** from a list of key-value pairs
#[doc(hidden)]
macro_rules! hashmap {
    ($($key:expr => $value:expr,)+) => { hashmap!($($key => $value),+) };
    ($($key:expr => $value:expr),*) => {
        {
            let _cap = count!(@count $($key),*);
            let mut _map = ::std::collections::HashMap::with_capacity(_cap);
            $(
                let _ = _map.insert($key, $value);
            )*
            _map
        }
    };
}

/// Arguments maintained as a map of string keys to a list of values.
/// It is similar to url.Values.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Args(HashMap<String, Vec<String>>);

impl Args {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(&mut self, key: &str, value: &str) {
        // value either exists or is allocated here.
        self.entry(key.to_string()).or_default();

        // therefor value should never be None and it is safe to unwrap.
        self.get_mut(key).unwrap().push(value.to_string());
    }
}

impl Deref for Args {
    type Target = HashMap<String, Vec<String>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Args {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Encode a name–value mapping so that it is suitable to go in the ARGS option
/// of an SMETHOD line. The output is sorted by key. The "ARGS:" prefix is not
/// added.
///
/// "Equal signs and commas [and backslashes] MUST be escaped with a backslash."
pub fn encode_smethod_args(maybe_args: Option<&Args>) -> String {
    if maybe_args.is_none() {
        return String::from("");
    }

    let escape = |s: &str| -> String { backslash_escape(s, vec!['=', ',']) };

    maybe_args
        .unwrap()
        .iter()
        .sorted()
        .map(|(key, values)| {
            values
                .iter()
                .map(|value| format!("{}={}", escape(key), escape(value)))
                .collect::<Vec<String>>()
                .join(",")
        })
        .collect::<Vec<String>>()
        .join(",")
}

fn backslash_escape(s: &str, set: Vec<char>) -> String {
    let mut result = String::new();
    s.chars().for_each(|a| {
        if a == '\\' || set.contains(&a) {
            result.push('\\');
        }
        result.push(a);
    });
    result
}

/// Return the index of the next unescaped byte in s that is in the term set, or
/// else the length of the string if no terminators appear. Additionally return
/// the unescaped string up to the returned index.
fn index_unescaped(s: &str, term: Vec<char>) -> Result<(usize, String), Error> {
    let mut unesc = String::new();
    let mut i: usize = 0;
    while i < s.len() {
        let mut c = s.chars().nth(i).unwrap();

        // is c a terminator character?
        if term.contains(&c) {
            break;
        }
        if c == '\\' {
            i += 1;
            if i >= s.len() {
                return Err(Error::ParseError(format!(
                    "nothing following final escape in \"{}\"",
                    s
                )));
            }
            c = s.chars().nth(i).unwrap();
        }
        unesc.push(c);
        i += 1;
    }
    Ok((i, unesc))
}

/// Parse a name–value mapping as from an encoded SOCKS username/password.
///
/// "First the '<Key>=<Value>' formatted arguments MUST be escaped, such that all
/// backslash, equal sign, and semicolon characters are escaped with a
/// backslash."
pub fn parse_client_parameters(params: &str) -> Result<Args, Error> {
    let mut args = Args::new();
    if params.is_empty() {
        return Ok(args);
    }

    let mut i: usize = 0;
    loop {
        let begin = i;

        // Read the key.
        let (offset, key) = index_unescaped(&params[i..], vec!['=', ';'])?;

        i += offset;
        // End of string or no equals sign?
        if i >= params.len() || params.chars().nth(i).unwrap() != '=' {
            return Err(Error::ParseError(format!(
                "parsing client params found no equals sign in {}",
                &params[begin..i]
            )));
        }

        // Skip the equals sign.
        i += 1;

        // Read the value.
        let (offset, value) = index_unescaped(&params[i..], vec![';'])?;

        i += offset;
        if key.is_empty() {
            return Err(Error::ParseError(format!(
                "parsing client params encountered empty key in {}",
                &params[begin..i]
            )));
        }
        args.add(&key, &value);

        if i >= params.len() {
            break;
        }

        // Skip the semicolon.
        i += 1;
    }

    Ok(args)
}

/// transport name to value mapping as from TOR_PT_SERVER_TRANSPORT_OPTIONS
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Opts(HashMap<String, Args>);

impl Opts {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
}

impl Deref for Opts {
    type Target = HashMap<String, Args>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Opts {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Parse a transport–name–value mapping as from TOR_PT_SERVER_TRANSPORT_OPTIONS.
///
/// "...a semicolon-separated list of <key>:<value> pairs, where <key> is a PT
/// name and <value> is a k=v string value with options that are to be passed to
/// the transport. Colons, semicolons, equal signs and backslashes must be
/// escaped with a backslash."
///
/// Example: `scramblesuit:key=banana;automata:rule=110;automata:depth=3`
pub fn parse_server_transport_options(s: &str) -> Result<Opts, Error> {
    let mut opts = Opts::new();
    if s.is_empty() {
        return Ok(opts);
    }
    let mut i: usize = 0;
    loop {
        let begin = i;
        // Read the method name.
        let (offset, method_name) = index_unescaped(&s[i..], vec![':', '=', ';'])?;

        i += offset;
        // End of string or no colon?
        if i >= s.len() || s.chars().nth(i).unwrap() != ':' {
            return Err(Error::ParseError(format!("no colon in {}", &s[begin..i])));
        }
        // Skip the colon.
        i += 1;

        // Read the key.
        let (offset, key) = index_unescaped(&s[i..], vec!['=', ';'])?;

        i += offset;
        // End of string or no equals sign?
        if i >= s.len() || s.chars().nth(i).unwrap() != '=' {
            return Err(Error::ParseError(format!(
                "no equals sign in {}",
                &s[begin..i]
            )));
        }
        // Skip the equals sign.
        i += 1;

        // Read the value.
        let (offset, value) = index_unescaped(&s[i..], vec![';'])?;

        i += offset;
        if method_name.is_empty() {
            return Err(Error::ParseError(format!(
                "empty method name in {}",
                &s[begin..i]
            )));
        }
        if key.is_empty() {
            return Err(Error::ParseError(format!("empty key in {}", &s[begin..i])));
        }

        opts.entry(method_name)
            .and_modify(|e| e.add(&key, &value))
            .or_insert(Args(hashmap! {key => vec![value]}));

        if i >= s.len() {
            break;
        }
        // Skip the semicolon.
        i += 1;
    }
    Ok(opts)
}

impl std::str::FromStr for Args {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

#[allow(clippy::to_string_trait_impl)]
impl std::string::ToString for Args {
    fn to_string(&self) -> String {
        String::from("")
    }
}

impl std::str::FromStr for Opts {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

#[allow(clippy::to_string_trait_impl)]
impl std::string::ToString for Opts {
    fn to_string(&self) -> String {
        String::from("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_args() {
        let args = Args(hashmap!(
            String::from("a") => vec![],
            String::from("b") => vec![String::from("value")],
            String::from("c") => vec![String::from("v1"), String::from("v2"), String::from("v3")]
        ));

        let empty = Args::new();

        if let Some(v) = empty.get("a") {
            panic!("unexpected result from `get` on empty Args: {:?}", v);
        }

        if let Some(v) = args.get("a") {
            panic!("unexpected get success for \"{}\" → {:?}", "a", v);
        }

        match args.get("b") {
            Some(v) => assert_eq!(
                v[0], "value",
                "Get({}) → {:?} (expected {})",
                "b", v, "value"
            ),
            None => panic!("Unexpected Get failure for \"{}\"", "b"),
        }

        match args.get("c") {
            Some(v) => assert_eq!(v[0], "v1", "Get({}) → {:?} (expected {})", "c", v, "v1"),
            None => panic!("Unexpected Get failure for \"{}\"", "c"),
        }

        if let Some(v) = args.get("d") {
            panic!("unexpected get success for \"{}\" → {:?}", "d", v);
        }
    }

    #[test]
    fn test_add_args() {
        let mut args = Args::new();
        let mut expected = Args::new();
        assert_eq!(args, expected, "{:?} != {:?}", args, expected);

        args.add("k1", "v1");
        expected = Args(hashmap!(
            String::from("k1")=>vec![String::from("v1")]
        ));
        assert_eq!(args, expected, "{:?} != {:?}", args, expected);

        args.add("k2", "v2");
        expected = Args(hashmap!(
            String::from("k1")=>vec![String::from("v1")],
            String::from("k2") => vec![String::from("v2")]
        ));
        assert_eq!(args, expected, "{:?} != {:?}", args, expected);

        args.add("k1", "v3");
        expected = Args(hashmap!(
            String::from("k1") => vec![String::from("v1"), String::from("v3")],
            String::from("k2") => vec![String::from("v2")]
        ));
        assert_eq!(args, expected, "{:?} != {:?}", args, expected);
    }

    #[test]
    fn test_parse_client_parameters() {
        let bad_cases = vec![
            "key",
            "key\\",
            "=value",
            "==value",
            "==key=value",
            "key=value\\",
            "a=b;key=value\\",
            "a;b=c",
            ";",
            "key=value;",
            ";key=value",
            "key\\=value",
        ];
        let good_cases = vec![
            ("", HashMap::new()),
            ("key=", hashmap!("key" => vec![""])),
            ("key==", hashmap!("key" => vec!["="])),
            ("key=value", hashmap!("key" => vec!["value"])),
            ("a=b=c", hashmap!("a" => vec!["b=c"])),
            ("a=bc==", hashmap!("a" => vec!["bc=="])),
            ("a\\=b=c", hashmap!("a=b" => vec!["c"])),
            ("key=a\nb", hashmap!("key" => vec!["a\nb"])),
            ("key=value\\;", hashmap!("key" => vec!["value;"])),
            ("key=\"value\"", hashmap!("key" => vec!["\"value\""])),
            ("\"key=value\"", hashmap!("\"key" => vec!["value\""])),
            (
                "key=\"\"value\"\"",
                hashmap!("key" => vec!["\"\"value\"\""]),
            ),
            (
                "key=value;key=value",
                hashmap!("key" => vec!["value", "value"]),
            ),
            (
                "key=value1;key=value2",
                hashmap!("key" => vec!["value1", "value2"]),
            ),
            (
                "key1=value1;key2=value2;key1=value3",
                hashmap!("key1" => vec!["value1", "value3"], "key2" => vec!["value2"]),
            ),
            (
                "\\;=\\;;\\\\=\\;",
                hashmap!(";" => vec![";"], "\\" => vec![";"]),
            ),
            (
                "shared-secret=rahasia;secrets-file=/tmp/blob",
                hashmap!("shared-secret" => vec!["rahasia"], "secrets-file" => vec!["/tmp/blob"]),
            ),
            (
                "rocks=20;height=5.6",
                hashmap!("rocks" => vec!["20"], "height" => vec!["5.6"]),
            ),
        ];

        for input in bad_cases {
            match parse_client_parameters(input) {
                Ok(_) => panic!("{} unexpectedly succeeded", input),
                Err(_) => {} // TODO: Validate error types
                             // Err(_) => { todo!("Validate error types")}
                             // Err(err) => assert_eq!(err, Box::new(Error::Unknown)),
            }
        }

        for (input, exected_map) in good_cases.iter() {
            // Convert all &str to String to keep tests readable
            let expected = Args(
                exected_map
                    .iter()
                    .map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect()))
                    .collect(),
            );

            match parse_client_parameters(input) {
                Ok(args) => assert_eq!(
                    args, expected,
                    "{} → {:?} (expected {:?})",
                    input, args, expected
                ),
                Err(err) => panic!("{} unexpectedly returned an error: {}", input, err),
            }
        }
    }

    #[test]
    fn parse_good_server_transport_options() {
        let good_cases = [
            ("", hashmap! {}),
            (
                "t:k=v",
                hashmap! {
                    "t" => hashmap!{"k" => vec!["v"]}
                },
            ),
            (
                "t:k=v=v",
                hashmap! {
                    "t" => hashmap!{"k" => vec!["v=v"]},
                },
            ),
            (
                "t:k=vv==",
                hashmap! {
                    "t" => hashmap!{"k" => vec!["vv=="]},
                },
            ),
            (
                "t1:k=v1;t2:k=v2;t1:k=v3",
                hashmap! {
                    "t1" => hashmap!{"k" => vec!["v1", "v3"]},
                    "t2" => hashmap!{"k" => vec!["v2"]},
                },
            ),
            (
                "t\\:1:k=v;t\\=2:k=v;t\\;3:k=v;t\\\\4:k=v",
                hashmap! {
                    "t:1" =>  hashmap!{"k" => vec!["v"]},
                    "t=2" =>  hashmap!{"k" => vec!["v"]},
                    "t;3" =>  hashmap!{"k" => vec!["v"]},
                    "t\\4" => hashmap!{"k" => vec!["v"]},
                },
            ),
            (
                "t:k\\:1=v;t:k\\=2=v;t:k\\;3=v;t:k\\\\4=v",
                hashmap! {
                    "t" => hashmap!{
                        "k:1" =>  vec!["v"],
                        "k=2" =>  vec!["v"],
                        "k;3" =>  vec!["v"],
                        "k\\4" => vec!["v"],
                    },
                },
            ),
            (
                "t:k=v\\:1;t:k=v\\=2;t:k=v\\;3;t:k=v\\\\4",
                hashmap! {
                    "t" => hashmap!{"k" => vec!["v:1", "v=2", "v;3", "v\\4"]},
                },
            ),
            (
                "trebuchet:secret=nou;trebuchet:cache=/tmp/cache;ballista:secret=yes",
                hashmap! {
                    "trebuchet" => hashmap!{
                        "secret" => vec!["nou"],
                        "cache" => vec!["/tmp/cache"]
                    },
                    "ballista" =>  hashmap!{"secret" => vec!["yes"]},
                },
            ),
        ];
        for (input, expected) in good_cases {
            match parse_server_transport_options(input) {
                Ok(opts) => {
                    // Convert all &str to String to keep tests readable
                    let expected_opts = Opts(
                        expected
                            .iter()
                            .map(|(opt_key, args)| {
                                (
                                    opt_key.to_string(),
                                    Args(
                                        args.iter()
                                            .map(|(k, vs)| {
                                                (
                                                    k.to_string(),
                                                    vs.iter().map(|v| v.to_string()).collect(),
                                                )
                                            })
                                            .collect(),
                                    ),
                                )
                            })
                            .collect(),
                    );
                    assert_eq!(
                        opts, expected_opts,
                        "{} → {:?} (expected {:?})",
                        input, opts, expected
                    )
                }
                Err(err) => panic!("{:?} unexpectedly returned error {}", input, err),
            }
        }
    }

    #[test]
    fn parse_bad_server_transport_options() {
        let bad_cases = [
            "t\\",
            ":=",
            "t:=",
            ":k=",
            ":=v",
            "t:=v",
            "t:=v",
            "t:k\\",
            "t:k=v;",
            "abc",
            "t:",
            "key=value",
            "=value",
            "t:k=v\\",
            "t1:k=v;t2:k=v\\",
            "t:=key=value",
            "t:==key=value",
            "t:;key=value",
            "t:key\\=value",
        ];

        for input in bad_cases {
            match parse_server_transport_options(input) {
                Ok(_) => panic!("{} unexpectedly succeeded", input),
                Err(_) => {} // TODO: Validate error types
                             // Err(_) => {todo!("Validate error types")}
                             // Err(err) => assert_eq!(err, Box::new(Error::Unknown)),
            }
        }
    }

    #[test]
    fn test_encode_smethod_args() {
        let tests = [
            // (None, ""),
            (HashMap::new(), ""),
            (
                hashmap! {"j"=>vec!["v1", "v2", "v3"], "k"=>vec!["v1", "v2", "v3"]},
                "j=v1,j=v2,j=v3,k=v1,k=v2,k=v3",
            ),
            (
                hashmap! {"=,\\"=>vec!["=", ",", "\\"]},
                "\\=\\,\\\\=\\=,\\=\\,\\\\=\\,,\\=\\,\\\\=\\\\",
            ),
            (hashmap! {"secret"=>vec!["yes"]}, "secret=yes"),
            (
                hashmap! {"secret"=> vec!["nou"], "cache" => vec!["/tmp/cache"]},
                "cache=/tmp/cache,secret=nou",
            ),
        ];

        assert_eq!("", encode_smethod_args(None));

        for (input_map, expected) in tests.iter() {
            let input = Args(
                input_map
                    .iter()
                    .map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect()))
                    .collect(),
            );

            let encoded = encode_smethod_args(Some(&input));
            assert_eq!(
                &encoded, expected,
                "{:?} → {} (expected {})",
                input, encoded, expected
            )
        }
    }
}

/*
pub fn parse_smethod_args(
    args: impl AsRef<str>,
) -> Result<HashMap<String, String>, Cow<'static, str>> {
    let words = args.as_ref().split_whitespace();

    let mut parsed_args = HashMap::new();

    // NOTE(eta): pt-spec.txt seems to imply these options can't contain spaces, so
    //            we work under that assumption.
    //            It also doesn't actually parse them out -- but seeing as the API to
    //            feed these back in will want them as separated k/v pairs, I think
    //            it makes sense to here.
    for option in words {
        if let Some(mut args) = option.strip_prefix("ARGS:") {
            while !args.is_empty() {
                let (k, v, rest) = parse_one_smethod_arg(args)
                    .map_err(|e| Cow::from(format!("failed to parse SMETHOD ARGS: {}", e)))?;
                if parsed_args.contains_key(&k) {
                    // At least check our assumption that this is actually k/v
                    // and not Vec<(String, String)>.
                    warn!("PT SMETHOD arguments contain repeated key {}!", k);
                }
                parsed_args.insert(k, v);
                args = rest;
            }
        }
    }

    Ok(parsed_args)
}

/// Chomp one key/value pair off a list of smethod args.
/// Returns (k, v, unparsed rest of string).
/// Will also chomp the comma at the end, if there is one.
fn parse_one_smethod_arg(args: &str) -> Result<(String, String, &str), &'static str> {
    // NOTE(eta): Apologies for this looking a bit gnarly. Ideally, this is what you'd use
    //            something like `nom` for, but I didn't want to bring in a dep just for this.

    let mut key = String::new();
    let mut val = String::new();
    // If true, we're reading the value, not the key.
    let mut reading_val = false;
    let mut chars = args.chars();
    while let Some(c) = chars.next() {
        let target = if reading_val { &mut val } else { &mut key };
        match c {
            '\\' => {
                let c = chars
                    .next()
                    .ok_or("smethod arg terminates with backslash")?;
                target.push(c);
            }
            '=' => {
                if reading_val {
                    return Err("encountered = while parsing value");
                }
                reading_val = true;
            }
            ',' => break,
            c => target.push(c),
        }
    }
    if !reading_val {
        return Err("ran out of chars parsing smethod arg");
    }
    Ok((key, val, chars.as_str()))
}

*/
