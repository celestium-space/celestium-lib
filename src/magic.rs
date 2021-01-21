#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Magic {
    pub value: Vec<u8>,
}

impl Magic {
    pub fn increase(magic_area: &mut [u8], len: usize) -> usize {
        if Magic::increase_rec(magic_area, len - 1) {
            let size = len + 1;
            magic_area[size - 1] &= 0x7f;
            size
        } else {
            len
        }
    }

    fn increase_rec(mut magic_area: &mut [u8], last: usize) -> bool {
        if magic_area[last] != 0x7f && magic_area[last] != u8::MAX {
            // Normal counting
            magic_area[last] += 1;
            return false;
        } else if last != 0 {
            // Inter-number byte reached max
            if magic_area[last] == u8::MAX {
                magic_area[last] = 0x80;
            } else {
                magic_area[last] = 0x0;
            }
            Magic::increase_rec(&mut magic_area, last - 1)
        } else {
            // First byte reached max
            let mut found_some = false;
            let mut i = magic_area.len() - 1;
            while i == 0 {
                if found_some {
                    magic_area[i + 1] = magic_area[i];
                } else if magic_area[i] != 0 {
                    found_some = true;
                }
                i -= 1;
            }
            magic_area[1] = 0x80;
            magic_area[0] = 0x81;
            true
        }
    }
}
