#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Magic {
    pub value: Vec<u8>,
}

impl Magic {
    pub fn increase(magic_area: &mut [u8], len: usize) -> usize {
        if Magic::increase_rec(magic_area) {
            let size = len + 1;
            magic_area[size - 1] &= 0x7f;
            size
        } else {
            len
        }
    }

    fn increase_rec(magic_area: &mut [u8]) -> bool {
        if magic_area[0] != 0x7f && magic_area[0] != u8::MAX {
            // Normal counting
            magic_area[0] += 1;
            return false;
        } else if magic_area[0] == u8::MAX {
            // Inter-number byte reached max
            magic_area[0] = 0x80;
            Magic::increase_rec(&mut magic_area[1..])
        } else {
            // Last byte reached max
            magic_area[0] += 1;
            magic_area[1] = 1;
            true
        }
    }
}
