//this is the implementatation of poly1305 in rust using as a base
//this implementation https://github.com/floodyberry/poly1305-donna using 64 bit * 64 bit = 128 bit multiplication abd 64 bit addition
//there is already an implementatation on rust using this method but on 32 bits
//you can find that here
//https://github.com/cesarb/chacha20-poly1305-aead/blob/master/src/poly1305.rs
//this was made as an exercise for my master thesis work
use std::convert::TryInto;

//this is just for conveniance
fn pop(arr: &[u8]) -> [u8; 8] {
    arr.try_into().expect("slice with incorrect length")
}


fn from_le_bytes(arr: &[u8]) -> u64 {
	let a = u64::from_le_bytes(pop(arr));
	a
}

//splits 128 bits into two integers and takes the bottom half.(rust should have a native function to do this because this is done natively either  way so it is quite redundant to do this)
fn lo(src: u128) -> u64 {
	let bottom_mask: u128 = ((1 as u128) << 64) -1;
	let lo = (src & bottom_mask) as u64;
	lo
}

//structure of the state
struct Poly1305 {
	
	r: [u64;3],
	h: [u64;3],
	pad: [u64;2],
	leftover: usize,
	buffer: [u8;16],
	f_block: u8,

}


impl Poly1305 {
	
	pub fn new(key: &[u8]) -> Self {
		
		assert!(key.len() == 32);
		let mut t0 = from_le_bytes(&key[ 0.. 8]);
		let mut t1 = from_le_bytes(&key[ 8.. 16]);
		
		Poly1305 {
			
			h: [0;3],
			
			r: [(t0 & 0xffc0fffffff),
				(((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff),
				(((t1 >> 24)) & 0x00ffffffc0f)],
			
			pad: [from_le_bytes(&key[16..24]),
				  from_le_bytes(&key[24..32])],
			
			leftover: 0,
			f_block: 0,
			buffer: [0;16]
					
		}
	}
	
	
	pub fn block(&mut self, m: &[u8], b:  &mut usize){
		
		let hibit: u64 = if self.f_block == 0 {1<<40} else {0};
		
		let mut bytes: usize = *b;
		
		let mut d0: u128 = 0;
		let mut d1: u128 = 0;
		let mut d2: u128 = 0;
		let mut d: u128 = 0;
		
		let mut r0: u64 = self.r[0];
		let mut r1: u64 = self.r[1];
		let mut r2: u64 = self.r[2];
		
		
		let mut h0: u64 = self.h[0];
		let mut h1: u64 = self.h[1];
		let mut h2: u64 = self.h[2];
		
		let mut s1: u64 = r1 * (5 << 2);
		let mut s2: u64 = r2 * (5 << 2);
		let mut i: usize = 0;
		
		while bytes >= 16 {
			
			/* h += m[i] */
			let mut t0: u64 = from_le_bytes(&m[i..i+8]);
			let mut t1: u64 = from_le_bytes(&m[i+8..i+16]);
			
			h0 += ( t0                    ) & 0xfffffffffff;
			h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffff;
			h2 += (((t1 >> 24)             ) & 0x3ffffffffff) | hibit;
			
			
			
			/* h *= r */
			let mut d0: u128 = h0 as u128 * r0 as u128;
			let mut d:  u128 = h1 as u128 * s2 as u128;
			d0 += d;
			d = h2 as u128 * s1 as u128;
			d0 += d;
			
			
			
			d1 = h0 as u128 * r1 as u128;
			d = h1 as u128 * r0 as u128;
			d1 += d;
			d = h2 as u128 * s2 as u128;
			d1 += d;
			d2 = h0 as u128 * r2 as u128;
			d = h1 as u128 * r1 as u128;
			d2 += d;
			d = h2 as u128 * r0 as u128;
			d2 += d;
			
			
			
			
			/* (partial) h %= p */
			let mut c: u64 = (d0 >> 44) as u64;
			h0 = lo(d0) & 0xfffffffffff;
			d1 = d1 + c as u128;
			c = (d1 >> 44) as u64;
			h1 = lo(d1) & 0xfffffffffff;
			d2 = d2 + c as u128;
			c = (d2 >> 42) as u64;
			h2 = lo(d2) & 0x3ffffffffff;
			h0  += c * 5;
			c = (h0 >> 44) as u64;
			h0 =    h0  & 0xfffffffffff;
			h1  += c;
			
			
			i += 16;
			bytes -= 16;	
			
		}
		
		self.h[0] = h0;
		self.h[1] = h1;
		self.h[2] = h2;
			
	
	}
	
	pub fn finish(&mut self, mac: &mut [u8]){
		
		/* process the remaining block */
		if self.leftover > 0 {
			
	
			let mut i: usize = self.leftover;
			//println!("{:?}", self.leftover);
			self.buffer[i] = 1;
			i += 1;
			
			while i < 16 {
				
				self.buffer[i] = 0;
				i += 1;
			
			}
			
			self.f_block = 1;
			let mut msg: [u8;16] = [0;16];
			msg.clone_from_slice(&self.buffer);
			self.block(&msg, &mut 16);	
		
		}
		
		/* fully carry h */
		let mut h0: u64 = self.h[0];
		let mut h1: u64 = self.h[1];
		let mut h2: u64 = self.h[2];
		
		let mut c: u64 = h1 >> 44;
		h1 &= 0xfffffffffff;
		h2 += c;     c = h2 >> 42; h2 &= 0x3ffffffffff;
		h0 += c * 5; c = h0 >> 44; h0 &= 0xfffffffffff;
		h1 += c;     c = h1 >> 44; h1 &= 0xfffffffffff;
		h2 += c;     c = h2 >> 42; h2 &= 0x3ffffffffff;
		h0 += c * 5; c = h0 >> 44; h0 &= 0xfffffffffff;
		h1.wrapping_add(c);
		
		
		/* compute h + -p */
		let mut g0: u64 = h0 + 5; c = g0 >> 44; g0 &= 0xfffffffffff;
		let mut g1: u64 = h1 + c; c = g1 >> 44; g1 &= 0xfffffffffff;
		let mut g2: u64 = h2 + c.wrapping_sub(((1 as u64) << 42));
		
		
		
		/* select h if h < p, or h + -p if h >= p */
		c = (g2 >> 63).wrapping_sub(1);
		//c = (g2 >> (64 - 1)) - 1;
		g0 &= c;
		g1 &= c;
		g2 &= c;
		c = !c;
		h0 = (h0 & c) | g0;
		h1 = (h1 & c) | g1;
		h2 = (h2 & c) | g2;
		
		
		
		/* h = (h + pad) */
		let t0: u64 = self.pad[0];
		let t1: u64 = self.pad[1];
		
		
		h0 +=  t0                     & 0xfffffffffff    ;	 c = h0 >> 44; h0 &= 0xfffffffffff;
		h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff).wrapping_add(c); c = h1 >> 44; h1 &= 0xfffffffffff;
		h2 += (((t1 >> 24)             ) & 0x3ffffffffff).wrapping_add(c);                 h2 &= 0x3ffffffffff;
		
	
		
		/* mac = h % (2^128) */
		h0 = ((h0      ) | (h1 << 44));
		h1 = ((h1 >> 20) | (h2 << 24));
		
		//let m_aux: [u8;16] = [0;16]; 
		let m1 = h0.to_le_bytes();
		let m2 =h1.to_le_bytes();
		mac[0..8].clone_from_slice(&m1[0..8]);
		mac[8..16].clone_from_slice(&m2[0..8]); 
		
	}
	
	pub fn update(&mut self, m: &[u8], b: &mut usize){
		
		let mut i: usize = 0;
		let mut want_a: usize = 0;
		let mut want_b: usize = 0;
		
		/* process full blocks */
		if *b >= 16 {
			want_b = (*b & !(16 - 1));
			self.block(&m[want_a..],&mut want_b);
			*b -= want_b;
		}
		
		/* store leftover */
		if *b > 0 {
			let mut i: usize = 0;
			while i < *b {
				self.buffer[self.leftover + i] = m[want_b + i];
				i += 1
			}
			self.leftover += *b;
		}
		
	}
	
	
}







//this is used for testing
fn main(){
	
	let key = [0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
	               0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
	               0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
	               0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b];

	let msg = b"Cryptographic Forum Research Group";
	let mut state = Poly1305::new(&key);
	state.update(&msg[0..],&mut 34);
	let mut mac: [u8;16] = [0; 16];
	state.finish(&mut mac);   
	assert!(key.len()==32);
	let s_mac = String::from_utf8_lossy(&mac);
	println!("{:?}", mac);
	
}