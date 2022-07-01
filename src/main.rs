mod utils;

mod prelude {
 pub use crate::utils::ToByteArray;
}

use crate::prelude::*;

fn main() {
    String::from("asdf").to_byte_array();
}
