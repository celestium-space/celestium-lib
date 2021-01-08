pub trait Serialize {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
    ) -> Result<Box<Self>, String>;
    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String>;
}

pub trait StaticSized {
    fn serialized_len() -> usize;
}

pub trait DynamicSized {
    fn serialized_len(&self) -> usize;
}
