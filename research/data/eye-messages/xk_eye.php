<?php

	define("U32_MAX", "4294967296");

	// Message ids range from 0~8
	$id	= min(max($argv[1] ?? 0, 0), 8);

	for ($i = 0; $i < 9; $i++) {
		print "$i --------------------------------------\n";
		print decode_message($i) ."\n";
	}
	

	function decode_message($id) {

		// Messages are processed in reverse order
		// but here we can just reverse the array instead
		$message	= array_reverse(get_message($id));
		$out	= [];

		// For each pair of 32-bit integers...
		foreach ($message as $nums) {
			// Convert the pair into a 64 bit number
			// and remove first character (always 0)
			$a		= bcadd( (string) $nums[0], bcmul( (string) $nums[1], U32_MAX) );
			$a		= bcdiv($a, "7", 0);
	
			// Take the modulo 7 (character) + divide by 7
			do {
				$out[]	= intval(bcmod($a, 7, 0)) - 1;
				$a		= bcdiv($a, 7, 0);
			} while ($a !== "0");
		}
	
		// The order of characters is also reversed
		$out	= array_reverse($out);
		$outstr	= "";
		foreach ($out as $c) {
			$outstr .= $c . ($c === 5 ? "\n" : "");
		}

		return $outstr;
	
	}


	function get_message($id) {

		$message	= array_fill(0, 8, []);
		$num		= 0;

		// 0 -----------------------------------------
		$message[$num][] = [ 0x5634505c, 0xacf68674 ];
		$message[$num][] = [ 0x2c9ac076, 0x981e2346 ];
		$message[$num][] = [ 0x2e474a1f, 0x29848a73 ];
		$message[$num][] = [ 0xc220213a, 0x75a31019 ];
		$message[$num][] = [ 0x1fecf4e, 0x2c7aa564 ];
		$message[$num][] = [ 0x2bf7569a, 0xf9b307f9 ];
		$message[$num][] = [ 0x3e145ee9, 0xeb76f050 ];
		$message[$num][] = [ 0xb54a6af2, 0x993474bb ];
		$message[$num][] = [ 0x5eea05e8, 0x43ea988d ];
		$message[$num][] = [ 0xadde7d91, 0x4136e1da ];
		$message[$num][] = [ 0x101ef86, 0x472533a7 ];
		$message[$num][] = [ 0x3fe75e9e, 0x90a4b336 ];
		$message[$num][] = [ 0xc9b9c908, 0x863f83a7 ];
		$message[$num][] = [ 0x52329ab4, 0x20c91280 ];

		// 1 -----------------------------------------
		$num++;
		$message[$num][] = [ 0xb1c95194, 0xeaf95a7c ];
		$message[$num][] = [ 0x2ca1eeba, 0x981e2346 ];
		$message[$num][] = [ 0x2e474a1f, 0x29848a73 ];
		$message[$num][] = [ 0xac567db9, 0x75a31019 ];
		$message[$num][] = [ 0x56f0b2ae, 0x2c7a8998 ];
		$message[$num][] = [ 0x9dfd44ec, 0xf9b30744 ];
		$message[$num][] = [ 0x7b7555aa, 0x48353272 ];
		$message[$num][] = [ 0xcc6a521c, 0x993f346f ];
		$message[$num][] = [ 0xe9153d2e, 0x53c3db0d ];
		$message[$num][] = [ 0x7293312c, 0x628375f9 ];
		$message[$num][] = [ 0xe49c1fef, 0xb40dac02 ];
		$message[$num][] = [ 0xccc378b2, 0x537dbb53 ];
		$message[$num][] = [ 0x4d4eaf5f, 0xf319978d ];
		$message[$num][] = [ 0x40e1fc47, 0xbca3f152 ];
		$message[$num][] = [ 0xbf905626, 0x0 ];

		// 2 -----------------------------------------
		$num++;
		$message[$num][] = [ 0x1cf72f99, 0x8634c1ef ];
		$message[$num][] = [ 0x2ca1f81b, 0x981e2346 ];
		$message[$num][] = [ 0x2e474a1f, 0x29848a73 ];
		$message[$num][] = [ 0xe1637be9, 0x75a31019 ];
		$message[$num][] = [ 0xb914ade3, 0xe2cfe1d3 ];
		$message[$num][] = [ 0xb723d349, 0x786f45ab ];
		$message[$num][] = [ 0x48c7c97b, 0xbee5b2a5 ];
		$message[$num][] = [ 0xef63311a, 0x2cbc058b ];
		$message[$num][] = [ 0x655c358a, 0xae1bc859 ];
		$message[$num][] = [ 0x797cd4b3, 0x805b0e68 ];
		$message[$num][] = [ 0x64bf17b9, 0x87eb66f8 ];
		$message[$num][] = [ 0xc737f7dd, 0x40a4cabc ];
		$message[$num][] = [ 0x4f299b43, 0x8dfe0c08 ];
		$message[$num][] = [ 0xe0b4b2f4, 0x2aabf66d ];
		$message[$num][] = [ 0xfae456c4, 0x5a0d593c ];
		$message[$num][] = [ 0x72a8e6a, 0x2b885f6a ];
		$message[$num][] = [ 0x616cf703, 0x2d28 ];

		// 3 -----------------------------------------
		$num++;
		$message[$num][] = [ 0xba591cfd, 0xe339e9b5 ];
		$message[$num][] = [ 0x9f5fdb97, 0x40aa767c ];
		$message[$num][] = [ 0x6a205b2d, 0x292a2b08 ];
		$message[$num][] = [ 0xe906ad86, 0x2819fcb0 ];
		$message[$num][] = [ 0x2d7097c7, 0xb3ad535d ];
		$message[$num][] = [ 0x5f701c14, 0xe25103af ];
		$message[$num][] = [ 0x3d510e03, 0x7941b070 ];
		$message[$num][] = [ 0xe4ab73f, 0x7d50d317 ];
		$message[$num][] = [ 0x71e3af41, 0x2a497ecf ];
		$message[$num][] = [ 0xc25d5cb0, 0x87dfd311 ];
		$message[$num][] = [ 0xae0a79, 0xed860703 ];
		$message[$num][] = [ 0x7cb6914, 0x31468f6d ];
		$message[$num][] = [ 0x856d0002, 0xfac360d1 ];
		$message[$num][] = [ 0x9449c363, 0x47499296 ];
		$message[$num][] = [ 0x4b209af6, 0x0 ];

		// 4 -----------------------------------------
		$num++;
		$message[$num][] = [ 0x3f7f2d6f, 0xbc7824f9 ];
		$message[$num][] = [ 0xd99610d2, 0xec6ae62e ];
		$message[$num][] = [ 0x9c10ea2f, 0x2929e6c7 ];
		$message[$num][] = [ 0xaf3a9d6b, 0x3f77f101 ];
		$message[$num][] = [ 0x72274d9d, 0x867e7502 ];
		$message[$num][] = [ 0x89efd32a, 0x888f5ab2 ];
		$message[$num][] = [ 0x80a77a7b, 0xae3ea520 ];
		$message[$num][] = [ 0x1bcfa31f, 0x7d640202 ];
		$message[$num][] = [ 0xc2abe496, 0x40c36cc3 ];
		$message[$num][] = [ 0x8a590904, 0x2584e684 ];
		$message[$num][] = [ 0xeb45f210, 0xe9d5b567 ];
		$message[$num][] = [ 0x1f571e0d, 0x40d17965 ];
		$message[$num][] = [ 0x7628b91f, 0xec75a14d ];
		$message[$num][] = [ 0x70e3ed4a, 0x7ee7240c ];
		$message[$num][] = [ 0xd76e5ea0, 0xb536c25e ];
		$message[$num][] = [ 0xd4da8afe, 0x2a9c303c ];
		$message[$num][] = [ 0xec314373, 0xedaf6daf ];
		$message[$num][] = [ 0x96eca434, 0x61f5113b ];
		$message[$num][] = [ 0x9fb1a087, 0x281000c2 ];
		$message[$num][] = [ 0x8a797d1, 0x0 ];

		// 5 -----------------------------------------
		$num++;
		$message[$num][] = [ 0x9445728a, 0x7e7550ff ];
		$message[$num][] = [ 0xd0f6513, 0xf30328d5 ];
		$message[$num][] = [ 0x9d27ce70, 0x292a0d5c ];
		$message[$num][] = [ 0x52a05d69, 0xbfca758c ];
		$message[$num][] = [ 0xe8109a74, 0x251a1f3f ];
		$message[$num][] = [ 0x5dedc516, 0x24d30587 ];
		$message[$num][] = [ 0x44e5f584, 0xb3d39014 ];
		$message[$num][] = [ 0x5790c997, 0x82380e0a ];
		$message[$num][] = [ 0xb411f01b, 0xe2449c62 ];
		$message[$num][] = [ 0x7ebe9feb, 0xb5e7969a ];
		$message[$num][] = [ 0x4471d7ec, 0x4a9c0282 ];
		$message[$num][] = [ 0x866a064b, 0x313a62bf ];
		$message[$num][] = [ 0xa8f7fe37, 0x29b312b3 ];
		$message[$num][] = [ 0xeccf2773, 0x79186c2a ];
		$message[$num][] = [ 0x3f22c3ac, 0xb85b08f3 ];
		$message[$num][] = [ 0xf689a796, 0x286b232d ];
		$message[$num][] = [ 0x577b0f1, 0x4eeb3967 ];
		$message[$num][] = [ 0x42200715, 0x20c ];

		// 6 -----------------------------------------
		$num++;
		$message[$num][] = [ 0xd85141c4, 0x76b4f66f ];
		$message[$num][] = [ 0x910a0cde, 0x8f93f5f0 ];
		$message[$num][] = [ 0x84925ae2, 0x2929e6c7 ];
		$message[$num][] = [ 0x29a68a25, 0x40933e6d ];
		$message[$num][] = [ 0xc75f5618, 0xc57372ac ];
		$message[$num][] = [ 0x794787b0, 0xbb64926d ];
		$message[$num][] = [ 0xb2dbe0fe, 0xf1fe39ca ];
		$message[$num][] = [ 0x936186e5, 0x474efd70 ];
		$message[$num][] = [ 0x6cad7fcf, 0xc342342e ];
		$message[$num][] = [ 0x81bafa5d, 0xe7a638fd ];
		$message[$num][] = [ 0x40004d4a, 0x29a2c904 ];
		$message[$num][] = [ 0x5cdb6750, 0xb62839cb ];
		$message[$num][] = [ 0xfd8931dd, 0x8dfa2566 ];
		$message[$num][] = [ 0x30d69c9, 0xee71ed89 ];
		$message[$num][] = [ 0x22f7029a, 0xce69520b ];
		$message[$num][] = [ 0x4f349ac3, 0x4748bf1d ];
		$message[$num][] = [ 0x9690947d, 0x13c03 ];

		// 7 -----------------------------------------
		$num++;
		$message[$num][] = [ 0x789603e6, 0xe339e97e ];
		$message[$num][] = [ 0xb2c91190, 0x8f93f5e9 ];
		$message[$num][] = [ 0x84925ae2, 0x2929e6c7 ];
		$message[$num][] = [ 0x4feb4015, 0x409374a5 ];
		$message[$num][] = [ 0xf7e604ea, 0x94979e7e ];
		$message[$num][] = [ 0x1bcc357, 0x4a96793f ];
		$message[$num][] = [ 0x36f40675, 0xc355c0a8 ];
		$message[$num][] = [ 0xb0f85513, 0x2a752013 ];
		$message[$num][] = [ 0x1b30e279, 0xbc7decdd ];
		$message[$num][] = [ 0x8a93175e, 0xc62c6bc0 ];
		$message[$num][] = [ 0x63dafb6f, 0x9781e76a ];
		$message[$num][] = [ 0xf3ba1e66, 0xb0a58e3b ];
		$message[$num][] = [ 0x641fde95, 0x297c940b ];
		$message[$num][] = [ 0x7874c807, 0x95120e03 ];
		$message[$num][] = [ 0x1017d733, 0xf6a5f2ff ];
		$message[$num][] = [ 0xdf851acf, 0x9540156f ];
		$message[$num][] = [ 0x2fdb567c, 0x2167abfb ];

		// 8 -----------------------------------------
		$num++;
		$message[$num][] = [ 0xe3c3e1eb, 0x7e7550f0 ];
		$message[$num][] = [ 0x67eb65a7, 0x8f93f5f3 ];
		$message[$num][] = [ 0x84925ae2, 0x2929e6c7 ];
		$message[$num][] = [ 0x5d0b8d5d, 0x40935218 ];
		$message[$num][] = [ 0xa3e4e814, 0xc671e036 ];
		$message[$num][] = [ 0xdc181d46, 0x5047870a ];
		$message[$num][] = [ 0x3dbac96b, 0x85653473 ];
		$message[$num][] = [ 0xaa9846f1, 0x24ee71d2 ];
		$message[$num][] = [ 0xc9269dc8, 0x76ba6749 ];
		$message[$num][] = [ 0xa9c340c6, 0x8da82039 ];
		$message[$num][] = [ 0x32d0143b, 0x802c4c1b ];
		$message[$num][] = [ 0xb02e0347, 0x77df0666 ];
		$message[$num][] = [ 0x5cb83226, 0x8fbb8712 ];
		$message[$num][] = [ 0x99246bfc, 0x569c4f81 ];
		$message[$num][] = [ 0xa564670b, 0xb4e02af6 ];
		$message[$num][] = [ 0xeb81e037, 0x5159ba32 ];
		$message[$num][] = [ 0x8c, 0x0 ];


		return $message[$id];
	}

