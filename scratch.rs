use zeroize::Zeroize;

fn main() {
    let mut b: Box<[u8]> = vec![0xAB; 32].into_boxed_slice();
    let ptr = b.as_ptr();
    b.zeroize();
    
    // check what changed
    println!("ptr after zeroize: {:?}", b.as_ptr());
    println!("value at ptr: {}", unsafe { std::ptr::read(ptr) });
}
