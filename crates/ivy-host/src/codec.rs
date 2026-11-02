//! Version 2 of Ivy's local event/configuration codec. Schema-checked values keep
//! signed 64-bit sizes and attosecond durations intact on 32-bit WebAssembly.
use unicode_normalization::UnicodeNormalization;
pub const VERSION: u8 = 2;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Unsigned(u64),
    Signed(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(std::string::String),
    Fields(Vec<Value>),
    List(Vec<Value>),
    Optional(Option<Box<Value>>),
    Tagged { tag: u8, fields: Vec<Value> },
}
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Event,
    Effect,
    Effects,
    Config,
    Peers,
    Endpoints,
}
#[derive(Clone, Copy)]
enum Union {
    Event,
    Effect,
    Request,
    Command,
    JobResult,
    Job,
    Result,
    Connect,
    Send,
    Direction,
    Route,
    Mode,
}
#[derive(Clone, Copy)]
enum Type {
    U16,
    U32,
    U64,
    I64,
    Bool,
    Bytes,
    String,
    Key,
    PeerId,
    Duration,
    Peer,
    Volume,
    Choice(u8),
    Fields(&'static [Type]),
    List(&'static Type),
    Optional(&'static Type),
    Union(Union),
}
use Type::*;
const ENDPOINT: Type = Fields(&[String, String, U16]);
const ADDRESS: Type = Fields(&[String, U16]);
const ENTRY: Type = Fields(&[String, Bytes]);
const FAILURE: Type = Optional(&Choice(2));
fn schema(union: Union, tag: u8) -> Option<&'static [Type]> {
    Some(match union {
        Union::Event => match tag {
            0..=2 => &[],
            3 => &[
                U64,
                Type::Union(Union::Direction),
                Optional(&String),
                Optional(&String),
            ],
            4 | 6 | 7 | 9 | 11 => &[U64],
            5 => &[U64, Bytes],
            8 => &[U64, Type::Union(Union::Request)],
            10 => &[Type::Union(Union::Command)],
            12 => &[U64, Type::Union(Union::JobResult)],
            13 => &[Optional(&ADDRESS)],
            _ => return None,
        },
        Union::Request => match tag {
            0 | 2 => &[ENDPOINT],
            1 => &[ENDPOINT, U64, Optional(&String), Optional(&String)],
            3 => &[PeerId, String, Bytes],
            4 => &[Peer, String, Bytes],
            5 => &[PeerId],
            6 | 12 | 13 => &[Peer],
            7 => &[String, I64, I64],
            8 => &[Peer, String, I64, I64],
            9 => &[String, List(&Peer)],
            10 | 11 => &[String],
            14 => &[List(&Peer), String, I64, I64],
            _ => return None,
        },
        Union::Command => match tag {
            0 | 1 => &[PeerId],
            2 => &[String, Bytes],
            3 => &[String, U64],
            4 => &[String, PeerId],
            5 => &[Bool],
            6 => &[PeerId, Bool],
            7 => &[String],
            _ => return None,
        },
        Union::JobResult => match tag {
            0 => &[List(&ENTRY)],
            1 => &[List(&String)],
            2 => &[Bool],
            _ => return None,
        },
        Union::Effect => match tag {
            0 => &[U64, ENDPOINT],
            1 => &[U64, Bytes],
            2..=4 | 11 => &[U64],
            5 => &[U64, Peer, String, Bytes],
            6 => &[U64, Peer],
            7 => &[PeerId],
            8 => &[ADDRESS],
            9 => &[U64, Type::Union(Union::Result)],
            10 => &[U64, Type::Union(Union::Job)],
            12 => &[],
            13 => &[Duration],
            _ => return None,
        },
        Union::Job => match tag {
            0 => &[String, I64],
            1 => &[String],
            2 => &[Peer, String],
            _ => return None,
        },
        Union::Result => match tag {
            0 => &[Type::Union(Union::Connect)],
            1 => &[Type::Union(Union::Send)],
            2 | 6 => &[Bool],
            3 => &[Volume],
            4 => &[List(&Volume), Bool, Bool, FAILURE],
            5 => &[List(&ENDPOINT)],
            _ => return None,
        },
        Union::Connect => match tag {
            0 | 2 => &[],
            1 => &[Choice(6)],
            _ => return None,
        },
        Union::Send => match tag {
            0 => &[PeerId, Type::Union(Union::Route)],
            1..=3 => &[],
            _ => return None,
        },
        Union::Direction => match tag {
            0 => &[],
            1 => &[U64],
            _ => return None,
        },
        Union::Route => match tag {
            0 => &[],
            1 => &[Key, Bytes],
            _ => return None,
        },
        Union::Mode => match tag {
            0 | 1 => &[],
            2 => &[String],
            _ => return None,
        },
    })
}
fn root(kind: Kind) -> Type {
    match kind {
        Kind::Event => Type::Union(Union::Event),
        Kind::Effect => Type::Union(Union::Effect),
        Kind::Effects => List(&Type::Union(Union::Effect)),
        Kind::Peers => List(&PeerId),
        Kind::Endpoints => List(&ENDPOINT),
        Kind::Config => Fields(&[
            Key,
            Optional(&U16),
            Optional(&List(&ENDPOINT)),
            Optional(&List(&ENDPOINT)),
            Optional(&Bool),
            Optional(&Type::Union(Union::Mode)),
            Optional(&Bool),
            Optional(&Duration),
            Optional(&Duration),
            Optional(&Duration),
            Optional(&I64),
            Optional(&Bool),
            Optional(&U32),
            Optional(&I64),
            Optional(&I64),
            Optional(&I64),
            Optional(&I64),
            Optional(&I64),
            Optional(&I64),
        ]),
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(n)?;
        let bytes = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }
    fn integer(&mut self, n: usize) -> Option<u64> {
        Some(self.take(n)?.iter().fold(0, |n, b| (n << 8) | *b as u64))
    }
    fn fields(&mut self, types: &[Type]) -> Option<Vec<Value>> {
        types.iter().map(|t| self.read(*t)).collect()
    }
    fn read(&mut self, ty: Type) -> Option<Value> {
        Some(match ty {
            Choice(_) => {
                let n = self.integer(1)?;
                if matches!(ty,Choice(max) if n>max as u64) {
                    return None;
                }
                Value::Unsigned(n)
            }
            U16 => Value::Unsigned(self.integer(2)?),
            U32 => Value::Unsigned(self.integer(4)?),
            U64 => Value::Unsigned(self.integer(8)?),
            I64 => Value::Signed(self.integer(8)? as i64),
            Bool => Value::Bool(match self.integer(1)? {
                0 => false,
                1 => true,
                _ => return None,
            }),
            Key => Value::Bytes(self.take(32)?.to_vec()),
            Bytes | String | PeerId => {
                let size = usize::try_from(self.integer(4)?).ok()?;
                let bytes = self.take(size)?;
                match ty {
                    Bytes => Value::Bytes(bytes.to_vec()),
                    _ => {
                        let value = std::str::from_utf8(bytes).ok()?.to_owned();
                        Value::String(if matches!(ty, PeerId) {
                            normalize_peer_id(value)
                        } else {
                            value
                        })
                    }
                }
            }
            Fields(types) => Value::Fields(self.fields(types)?),
            Duration => {
                let fields = self.fields(&[I64, I64])?;
                let (Value::Signed(seconds), Value::Signed(attoseconds)) = (&fields[0], &fields[1])
                else {
                    unreachable!()
                };
                if !(-999_999_999_999_999_999..=999_999_999_999_999_999).contains(attoseconds)
                    || (*seconds > 0 && *attoseconds < 0)
                    || (*seconds < 0 && *attoseconds > 0)
                {
                    return None;
                }
                Value::Fields(fields)
            }
            Optional(inner) => Value::Optional(match self.integer(1)? {
                0 => None,
                1 => Some(Box::new(self.read(*inner)?)),
                _ => return None,
            }),
            List(inner) => {
                let count = usize::try_from(self.integer(4)?).ok()?;
                if count > self.bytes.len() - self.offset {
                    return None;
                }
                let mut values = Vec::new();
                for _ in 0..count {
                    values.push(self.read(*inner)?);
                }
                Value::List(values)
            }
            Type::Union(union) => {
                let tag = self.integer(1)? as u8;
                Value::Tagged {
                    tag,
                    fields: self.fields(schema(union, tag)?)?,
                }
            }
            Peer => {
                let fields = self.fields(&[
                    Key,
                    Choice(1),
                    Type::Union(Union::Route),
                    List(&ADDRESS),
                    U32,
                    Bytes,
                ])?;
                let Value::List(addresses) = &fields[3] else {
                    unreachable!()
                };
                let mut last: Option<(std::string::String, u64)> = None;
                for address in addresses {
                    let Value::Fields(f) = address else {
                        unreachable!()
                    };
                    let (Value::String(host), Value::Unsigned(port)) = (&f[0], &f[1]) else {
                        unreachable!()
                    };
                    let pair = (host.nfc().collect::<std::string::String>(), *port);
                    if last.as_ref().is_some_and(|p| *p >= pair) {
                        return None;
                    }
                    last = Some(pair);
                }
                Value::Fields(fields)
            }
            Volume => {
                let fields = self.fields(&[String, List(&ENTRY), Optional(&PeerId), FAILURE])?;
                let Value::List(entries) = &fields[1] else {
                    unreachable!()
                };
                let mut previous: Option<&str> = None;
                let mut distinct = std::collections::BTreeSet::new();
                for entry in entries {
                    let Value::Fields(f) = entry else {
                        unreachable!()
                    };
                    let Value::String(cid) = &f[0] else {
                        unreachable!()
                    };
                    if previous.is_some_and(|p| p.as_bytes() >= cid.as_bytes())
                        || !distinct.insert(cid.nfc().collect::<std::string::String>())
                    {
                        return None;
                    }
                    previous = Some(cid);
                }
                Value::Fields(fields)
            }
        })
    }
}
fn normalize_peer_id(value: std::string::String) -> std::string::String {
    let raw = if value.len() == 68
        && value
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("ed01"))
    {
        &value[4..]
    } else if value.len() == 64 {
        &value
    } else {
        return value;
    };
    if raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        raw.to_ascii_lowercase()
    } else {
        value
    }
}
/// Refuses unknown tags, truncations, trailing data and noncanonical structures.
pub fn decode(kind: Kind, bytes: &[u8]) -> Option<Value> {
    let mut reader = Reader { bytes, offset: 0 };
    if reader.integer(1)? != VERSION as u64 {
        return None;
    }
    let value = reader.read(root(kind))?;
    (reader.offset == bytes.len()).then_some(value)
}
fn write(ty: Type, value: &Value, out: &mut Vec<u8>) -> Option<()> {
    fn fields(types: &[Type], values: &[Value], out: &mut Vec<u8>) -> Option<()> {
        if types.len() != values.len() {
            return None;
        }
        for (ty, value) in types.iter().zip(values) {
            write(*ty, value, out)?;
        }
        Some(())
    }
    match (ty, value) {
        (Choice(_), Value::Unsigned(n)) => out.push(u8::try_from(*n).ok()?),
        (U16, Value::Unsigned(n)) => out.extend(u16::try_from(*n).ok()?.to_be_bytes()),
        (U32, Value::Unsigned(n)) => out.extend(u32::try_from(*n).ok()?.to_be_bytes()),
        (U64, Value::Unsigned(n)) => out.extend(n.to_be_bytes()),
        (I64, Value::Signed(n)) => out.extend(n.to_be_bytes()),
        (Bool, Value::Bool(b)) => out.push(*b as u8),
        (Key, Value::Bytes(b)) if b.len() == 32 => out.extend(b),
        (Bytes, Value::Bytes(b)) => {
            out.extend(u32::try_from(b.len()).ok()?.to_be_bytes());
            out.extend(b);
        }
        (String | PeerId, Value::String(s)) => {
            let normalized = if matches!(ty, PeerId) {
                normalize_peer_id(s.clone())
            } else {
                s.clone()
            };
            out.extend(u32::try_from(normalized.len()).ok()?.to_be_bytes());
            out.extend(normalized.as_bytes());
        }
        (Fields(types), Value::Fields(v)) => fields(types, v, out)?,
        (Duration, Value::Fields(v)) => fields(&[I64, I64], v, out)?,
        (Peer, Value::Fields(v)) => fields(
            &[
                Key,
                Choice(1),
                Type::Union(Union::Route),
                List(&ADDRESS),
                U32,
                Bytes,
            ],
            v,
            out,
        )?,
        (Volume, Value::Fields(v)) => {
            fields(&[String, List(&ENTRY), Optional(&PeerId), FAILURE], v, out)?
        }
        (List(inner), Value::List(v)) => {
            out.extend(u32::try_from(v.len()).ok()?.to_be_bytes());
            for value in v {
                write(*inner, value, out)?;
            }
        }
        (Optional(inner), Value::Optional(v)) => {
            out.push(v.is_some() as u8);
            if let Some(v) = v {
                write(*inner, v, out)?;
            }
        }
        (Type::Union(union), Value::Tagged { tag, fields: v }) => {
            out.push(*tag);
            fields(schema(union, *tag)?, v, out)?;
        }
        _ => return None,
    }
    Some(())
}
/// Encodes only schema-valid values; the canonical decoder validates ordering.
pub fn encode(kind: Kind, value: &Value) -> Option<Vec<u8>> {
    let mut bytes = vec![VERSION];
    write(root(kind), value, &mut bytes)?;
    decode(kind, &bytes)?;
    Some(bytes)
}
