	'use strict';
	//md5---------------------------------------------------
	function safeAdd (x, y) {
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	}

  /*
  * Bitwise rotate a 32-bit number to the left.
  */
	function bitRotateLeft (num, cnt) {
		return (num << cnt) | (num >>> (32 - cnt));
	}

  /*
  * These functions implement the four basic operations the algorithm uses.
  */
	function md5cmn (q, a, b, x, s, t) {
		return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
	}
	function md5ff (a, b, c, d, x, s, t) {
		return md5cmn((b & c) | ((~b) & d), a, b, x, s, t);
	}
	function md5gg (a, b, c, d, x, s, t) {
		return md5cmn((b & d) | (c & (~d)), a, b, x, s, t);
	}
	function md5hh (a, b, c, d, x, s, t) {
		return md5cmn(b ^ c ^ d, a, b, x, s, t);
	}
	function md5ii (a, b, c, d, x, s, t) {
		return md5cmn(c ^ (b | (~d)), a, b, x, s, t);
	}

  /*
  * Calculate the MD5 of an array of little-endian words, and a bit length.
  */
	function binlMD5 (x, len) {
		/* append padding */
		x[len >> 5] |= 0x80 << (len % 32);
		x[(((len + 64) >>> 9) << 4) + 14] = len;

		var i;
		var olda;
		var oldb;
		var oldc;
		var oldd;
		var a = 1732584193;
		var b = -271733879;
		var c = -1732584194;
		var d = 271733878;

		for (i = 0; i < x.length; i += 16) {
			olda = a;
			oldb = b;
			oldc = c;
			oldd = d;

			a = md5ff(a, b, c, d, x[i], 7, -680876936);
			d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
			c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
			b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
			a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
			d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
			c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
			b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
			a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
			d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
			c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
			b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
			a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
			d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
			c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
			b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);

			a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
			d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
			c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
			b = md5gg(b, c, d, a, x[i], 20, -373897302);
			a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
			d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
			c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
			b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
			a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
			d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
			c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
			b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
			a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
			d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
			c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
			b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);

			a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
			d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
			c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
			b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
			a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
			d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
			c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
			b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
			a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
			d = md5hh(d, a, b, c, x[i], 11, -358537222);
			c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
			b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
			a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
			d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
			c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
			b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);

			a = md5ii(a, b, c, d, x[i], 6, -198630844);
			d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
			c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
			b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
			a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
			d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
			c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
			b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
			a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
			d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
			c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
			b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
			a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
			d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
			c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
			b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);

			a = safeAdd(a, olda);
			b = safeAdd(b, oldb);
			c = safeAdd(c, oldc);
			d = safeAdd(d, oldd);
		}
		return [a, b, c, d];
	}

  /*
  * Convert an array of little-endian words to a string
  */
	function binl2rstr (input) {
		var i;
		var output = '';
		var length32 = input.length * 32;
		for (i = 0; i < length32; i += 8) {
			output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
		}
		return output;
	}

  /*
  * Convert a raw string to an array of little-endian words
  * Characters >255 have their high-byte silently ignored.
  */
	function rstr2binl (input) {
		var i;
		var output = [];
		output[(input.length >> 2) - 1] = undefined;
		for (i = 0; i < output.length; i += 1) {
			output[i] = 0;
		}
		var length8 = input.length * 8;
		for (i = 0; i < length8; i += 8) {
			output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
		}
		return output;
	}

  /*
  * Calculate the MD5 of a raw string
  */
	function rstrMD5 (s) {
		return binl2rstr(binlMD5(rstr2binl(s), s.length * 8));
	}

  /*
  * Calculate the HMAC-MD5, of a key and some data (raw strings)
  */
	function rstrHMACMD5 (key, data) {
		var i;
		var bkey = rstr2binl(key);
		var ipad = [];
		var opad = [];
		var hash;
		ipad[15] = opad[15] = undefined;
		if (bkey.length > 16) {
			bkey = binlMD5(bkey, key.length * 8);
		}
		for (i = 0; i < 16; i += 1) {
			ipad[i] = bkey[i] ^ 0x36363636;
			opad[i] = bkey[i] ^ 0x5C5C5C5C;
		}
		hash = binlMD5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
		return binl2rstr(binlMD5(opad.concat(hash), 512 + 128));
	}

	/*
  * Convert a raw string to a hex string
  */
	function rstr2hex (input) {
		var hexTab = '0123456789abcdef';
		var output = '';
		var x;
		var i;
		for (i = 0; i < input.length; i += 1) {
			x = input.charCodeAt(i);
			output += hexTab.charAt((x >>> 4) & 0x0F) +
				hexTab.charAt(x & 0x0F);
		}
		return output;
	}

  /*
  * Encode a string as utf-8
  */
	function str2rstrUTF8 (input) {
		return unescape(encodeURIComponent(input));
	}

  /*
  * Take string arguments and return either raw or hex encoded strings
  */
	function rawMD5 (s) {
		return rstrMD5(str2rstrUTF8(s));
	}
	function hexMD5 (s) {
		return rstr2hex(rawMD5(s));
	}
	function rawHMACMD5 (k, d) {
		return rstrHMACMD5(str2rstrUTF8(k), str2rstrUTF8(d));
	}
	function hexHMACMD5 (k, d) {
		return rstr2hex(rawHMACMD5(k, d));
	}

	function md5 (string, key, raw) {
		if (!key) {
			if (!raw) {
				return hexMD5(string);
			}
			return rawMD5(string);
		}
		if (!raw) {
			return hexHMACMD5(key, string);
		}
		return rawHMACMD5(key, string);
	}

	if (typeof define === 'function' && define.amd) {
		define(function () {
			return md5;
		});
	} else if (typeof module === 'object' && module.exports) {
		module.exports = md5;
	} else {
		$.md5 = md5;
	}
	//------------------------------------------------------
	
	
	const getRoomId = () =>{
		try {
			return window.$ROOM.room_id;
		} catch (e) {}
		try {
			return /rid=(\d+)/.exec(document.querySelector('.feedback-report-button').href)[1];
		} catch (e) {}
		try {
			return document.querySelector('.current').getAttribute('data-room_id');
		} catch (e) {}
		throw new Error('未找到RoomId');
	};
	//------------------------------------------------------------
	function douyuClient (ip, port, map) {
		function utf8ToUtf16(utf8_bytes) {
			var unicode_codes = [];
			var unicode_code = 0;
			var num_followed = 0;
			for (var i = 0; i < utf8_bytes.length; ++i) {
				var utf8_byte = utf8_bytes[i];
				if (utf8_byte >= 0x100) {
					// Malformed utf8 byte ignored.
				} else if ((utf8_byte & 0xC0) == 0x80) {
					if (num_followed > 0) {
						unicode_code = (unicode_code << 6) | (utf8_byte & 0x3f);
						num_followed -= 1;
					} else {
						// Malformed UTF-8 sequence ignored.
					}
				} else {
					if (num_followed === 0) {
						unicode_codes.push(unicode_code);
					} else {
						// Malformed UTF-8 sequence ignored.
					}
					if (utf8_byte < 0x80){  // 1-byte
						unicode_code = utf8_byte;
						num_followed = 0;
					} else if ((utf8_byte & 0xE0) == 0xC0) {  // 2-byte
						unicode_code = utf8_byte & 0x1f;
						num_followed = 1;
					} else if ((utf8_byte & 0xF0) == 0xE0) {  // 3-byte
						unicode_code = utf8_byte & 0x0f;
						num_followed = 2;
					} else if ((utf8_byte & 0xF8) == 0xF0) {  // 4-byte
						unicode_code = utf8_byte & 0x07;
						num_followed = 3;
					} else {
						// Malformed UTF-8 sequence ignored.
					}
				}
			}
			if (num_followed === 0) {
				unicode_codes.push(unicode_code);
			} else {
				// Malformed UTF-8 sequence ignored.
			}
			unicode_codes.shift();  // Trim the first element.

			var utf16_codes = [];
			for (var i = 0; i < unicode_codes.length; ++i) {
				var unicode_code = unicode_codes[i];
				if (unicode_code < (1 << 16)) {
					utf16_codes.push(unicode_code);
				} else {
					var first = ((unicode_code - (1 << 16)) / (1 << 10)) + 0xD800;
					var second = (unicode_code % (1 << 10)) + 0xDC00;
					utf16_codes.push(first);
					utf16_codes.push(second);
				}
			}
			return utf16_codes;
		}
		function convertUnicodeCodePointsToUtf16Codes(unicode_codes) {
		}
		function utf8_to_ascii( str ) {
    // return unescape(encodeURIComponent(str))
			const char2bytes = unicode_code => {
				var utf8_bytes = [];
				if (unicode_code < 0x80) {  // 1-byte
					utf8_bytes.push(unicode_code);
				} else if (unicode_code < (1 << 11)) {  // 2-byte
					utf8_bytes.push((unicode_code >>> 6) | 0xC0);
					utf8_bytes.push((unicode_code & 0x3F) | 0x80);
				} else if (unicode_code < (1 << 16)) {  // 3-byte
					utf8_bytes.push((unicode_code >>> 12) | 0xE0);
					utf8_bytes.push(((unicode_code >> 6) & 0x3f) | 0x80);
					utf8_bytes.push((unicode_code & 0x3F) | 0x80);
				} else if (unicode_code < (1 << 21)) {  // 4-byte
					utf8_bytes.push((unicode_code >>> 18) | 0xF0);
					utf8_bytes.push(((unicode_code >> 12) & 0x3F) | 0x80);
					utf8_bytes.push(((unicode_code >> 6) & 0x3F) | 0x80);
					utf8_bytes.push((unicode_code & 0x3F) | 0x80);
				}
				return utf8_bytes;
			};
			let o = [];
			for (let i = 0; i < str.length; i++) {
				o = o.concat(char2bytes(str.charCodeAt(i)));
			}
			return o.map(i => String.fromCharCode(i)).join('');
		}
		function ascii_to_utf8( str ) {
    // return decodeURIComponent(escape(str))
			let bytes = str.split('').map(i => i.charCodeAt(0));
			return utf8ToUtf16(bytes).map(i => String.fromCharCode(i)).join('');
		}
		function filterEnc (s) {
			s = s.toString();
			s = s.replace(/@/g, '@A');
			return s.replace(/\//g, '@S');
		}
		function filterDec (s) {
			s = s.toString();
			s = s.replace(/@S/g, '/');
			return s.replace(/@A/g, '@');
		}
		function douyuEncode (data) {
			return Object.keys(data).map(key => `${key}@=${filterEnc(data[key])}`).join('/') + '/';
		}
		function douyuDecode (data) {
			let out = {};
			data.split('/').filter(i => i.length > 2).some(i => {
				let e = i.split('@=');
				out[e[0]] = filterDec(e[1]);
			});
			return out;
		}
		function decodeList (list) {
			return list = list.split('/').filter(i => i.length > 2).map(filterDec).map(douyuDecode);
		}
		douyuClient.encode = douyuEncode;
		douyuClient.decode = douyuDecode;
		douyuClient.decodeList = decodeList;
		const ACJ = (id, data) => {
			if (typeof data == 'object') {
				data = douyuEncode(data);
			}
			_ACJ_([id, data]);
		};
		function closeHandler() {
			console.error('lost connection');
		}
		function errorHandler(errorstr) {
			console.error(errorstr);
		}
		
		/*
  const p32 = i => [i, i / 256, i / 65536, i / 16777216].map(i => String.fromCharCode(Math.floor(i) % 256)).join('');
  const u32 = s => s.split('').map(i => i.charCodeAt(0)).reduce((a, b) => b * 256 + a);
  return new Promise((resolve, reject) => {
    let send = null;
    let buffer = '';
    let bufLen = 0;
    let socket = new JSocket({
      connectHandler () {
        resolve(send);
      },
      dataHandler (data) {
        buffer += data;
        while (buffer.length >= 4) {
          let size = u32(buffer.substr(0, 4));
          if (buffer.length >= size) {
            let pkg = '';
            try {
              pkg = ascii_to_utf8(buffer.substr(12, size-8));
            } catch (e) {
              console.log('deocde fail', escape(buffer.substr(12, size-8)));
            }
            buffer = buffer.substr(size+4);
            if (pkg.length === 0) 
				continue;
            try {
              const rawString = pkg;
              pkg = douyuDecode(pkg);
              if (map) {
                let cb = map[pkg.type];
                if (cb) {
                  if (typeof cb == 'string') {
                    ACJ(cb, pkg);
                  } else {
                    map[pkg.type](pkg, send, {
                      ACJ: ACJ,
                      rawString: rawString,
                      decode: douyuDecode,
                      encode: douyuEncode
                    });
                  }
                } else {
                  map.default && map.default(pkg, send)
                }
              }
            } catch (e) {}
          } else {
            break;
          }
        }
      },
      closeHandler: closeHandler,
      errorHandler: errorHandler
    });
	  socket.connect(ip, port);
	  send = function send (data) {
      let msg = douyuEncode(data) + '\0';
      msg = utf8_to_ascii(msg);
      msg = p32(msg.length+8) + p32(msg.length+8) + p32(689) + msg;
      socket.writeFlush(msg);
    };*/
	};
	
	let _room_args = null;
	let douyuApi = function douyuApi (roomId) {
		console.log('douyu api', roomId);
		let blacklist = [];
		const getRoomArgs = () => {
			if (_room_args){
				return _room_args;
			}
			if (window.room_args) {
				return window.room_args;
			} else {
				return $ROOM.args;
			}
		};
		getRoomArgs();
		const randServer = () => {
			const servers = JSON.parse(decodeURIComponent(getRoomArgs().server_config));
			const i = Math.floor(Math.random() * servers.length);
			return servers[i];
		};
		const randDanmuServer = () => {
			const ports = [8601, 8602, 12601, 12602];
			const i = Math.floor(Math.random() * ports.length);
			return {
				ip: 'danmu.douyu.com',
				// ip: '211.91.140.131',
				port: ports[i]
			};
		};
		const getACF = key => {
			try {
				return new RegExp(`acf_${key}=(.*?);`).exec(document.cookie)[1];
			} catch (e) {
				return '';
			}
		};
		const loginreq = () => {
			const rt = Math.round(new Date().getTime() / 1000);
			const devid = getACF('did'); // md5(Math.random()).toUpperCase()
			const username = getACF('username');
			console.log('username', username, devid);
			return {
				type: 'loginreq',
				username: username,
				ct: 0,
				password: '',
				roomid: roomId,
				devid: devid,
				rt: rt,
				vk: md5(`${rt}7oE9nPEG9xXV69phU31FYCLUagKeYtsF${devid}`),
				ver: '2016102501',
				biz: getACF('biz'),
				stk: getACF('stk'),
				ltkid: getACF('ltkid')
			};
		};
		const keepalive = () => {
			return {
				type: 'keeplive',
				tick: Math.round(new Date().getTime() / 1000)
			};
		};
		let server = randServer();
		let serverSend;
		let danmuSend;
		douyuClient(server.ip, server.port, {
			initcl: 'room_data_chatinit',
			memberinfores: 'room_data_info',
			ranklist: 'room_data_cqrank',
			rsm: 'room_data_brocast',
			loginres (data, send, {ACJ}) {
				send(keepalive());
				setInterval(() => send(keepalive()), 30*1000);
				ACJ('room_data_login', data);
				ACJ('room_data_getdid', {
					devid: getACF('did')
				});
			},
			keeplive (data, send, {ACJ, rawString}) {
				ACJ('room_data_userc', data.uc);
				ACJ('room_data_tbredpacket', rawString);
			},
			setmsggroup (data, send) {
				danmuSend({
					type: 'joingroup',
					rid: data.rid,
					gid: data.gid
				});
			},
			default (data, send, {ACJ}) {
				ACJ('room_data_handler', data);
				console.log('ms', data);
			}
		});
		/*.then(send => {
			send(loginreq());
			serverSend = send;
		});
		server = randDanmuServer();
		*/
  // 
		const chatmsgHandler = (data, send, {ACJ, encode}) => {
			if (blacklist.includes(data.uid)) {
				console.log('black');
			}
			try {
				window.postMsg({
					type: "DANMU",
					data: data
				}, "*");
			} catch (e) {
				console.error('wtf', e);
			}
			ACJ('room_data_chat2', data);
			if (window.BarrageReturn) {
				window.BarrageReturn(encode(data));
			}
		};
		douyuClient(server.ip, server.port, {
			chatmsg: chatmsgHandler,
			chatres: 'room_data_chat2',
			initcl: 'room_data_chatinit',
			dgb: 'room_data_giftbat1',
			dgn: 'room_data_giftbat1',
			spbc: 'room_data_giftbat1',
			uenter: 'room_data_nstip2',
			upgrade: 'room_data_ulgrow',
			newblackres: 'room_data_sys',
			ranklist: 'room_data_cqrank',
			rankup: 'room_data_ulgrow',
			gift_title: 'room_data_schat',
			rss: 'room_data_state',
			srres: 'room_data_wbsharesuc',
			onlinegift: 'room_data_olyw',
			// ggbr: '',
			default (data, send, {ACJ}) {
				ACJ('room_data_handler', data);
				console.log('dm', data);
			}
		});
			/*.then(send => {
			send(loginreq());
			setInterval(() => send(keepalive()), 30*1000);
			danmuSend = send;
		});*/
		const repeatPacket = text => douyuClient.decode(text);
		const jsMap = {
			js_rewardList: {
				type: 'qrl',
				rid: roomId
			},
			js_queryTask: {
				type: 'qtlnq'
			},
			js_newQueryTask: {
				type: 'qtlq'
			},
			js_getRankScore: repeatPacket,
			js_sendmsg (msg) {
				msg = douyuClient.decode(msg);
				msg.type = 'chatmessage';
				return msg;
			},
			js_giveGift (gift) {

				gift = douyuClient.decode(gift);
				if (gift.type === 'dn_s_gf') {
					gift.type = 'sgq';
					gift.bat = 0;
				}
				console.log('giveGift', gift);
				return gift;
			},
			js_GetHongbao: repeatPacket,
			js_UserHaveHandle () {},
			js_myblacklist (list) {
				console.log('add blacklist', list);
				blacklist = list.split('|');
			}
		};
		return {
			hookExe () {
				const api = require('douyu/page/room/base/api');
				const hookd = function hookd (...args) {
					let req = jsMap[args[0]];
					if (req) {
						if (typeof req == 'function') {
							req = req.apply(null, args.slice(1));
						}
						req && serverSend(req)
					} else {
						console.log('exe', args);
						try {
							return oldExe.apply(api, args);
						} catch (e) {}
					}
				};
				if (api) {
					let oldExe = api.exe;
					if (oldExe !== hookd) {
						api.exe = hookd;
					}
				} else if (window.thisMovie) {
					window.thisMovie = () => new Proxy({}, {
						get (target, key, receiver) {
							return (...args) => hookd.apply(null, [key].concat(args));
						},
						set (target, key, receiver) {
						}
					});
				}
			},
			sendDanmu (content) {
				serverSend({
					col: '0',
					content: content,
					dy: '',
					pid: '',
					sender: '702735',
					type: 'chatmessage'
				});
			},
			serverSend (c) {
				return serverSend(c);
			}
		};
	};


	let api = douyuApi(getRoomId());
	api.hookExe();
	window.addEventListener('message', event => {
		if (event.source != window)
			return;

		if (event.data.type && (event.data.type == "SENDANMU")) {
			const data = event.data.data;
			api.sendDanmu(data);
		}
	}, false);
  //api.sendDanmu
	window.api = api;
	//-------------------------------------------------
	function getSourceURL (rid, cdn = 'ws', rate = '0') {
		const API_KEY = 'A12Svb&%1UUmf@hC';
		const tt = Math.round(new Date().getTime() / 60 / 1000);
		const did = md5(Math.random().toString()).toUpperCase();
		const signContent = [rid, did, API_KEY, tt].join('');
		const sign = md5(signContent);
		let body = {
			'cdn': cdn,
			'rate': rate,
			'ver': '2016102501',
			'tt': tt,
			'did': did,
			'sign': sign
		};
		body = Object.keys(body).map(key => `${key}=${encodeURIComponent(body[key])}`).join('&');
		
		return fetch(`https://www.douyu.com/lapi/live/getPlay/${rid}`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			body: body
		})
			.then(res => res.json())
			.then(videoInfo => {
			
			const baseUrl = videoInfo.data.rtmp_url;
			const livePath = videoInfo.data.rtmp_live;
			if (baseUrl && livePath) {
				const videoUrl = `${baseUrl}/${livePath}`;
				console.log('RoomId', rid, 'SourceURL:', videoUrl);
				
				return videoUrl;
			} else {
				alert("未开播或获取失败");
				throw new Error('未开播或获取失败');
			}
		});
	}
	var videoUrl1=getSourceURL(getRoomId());	
	//-------------------------------
	const getACF = key => {
		try {
			return new RegExp(`acf_${key}=(.*?);`).exec(document.cookie)[1];
		} catch (e) {
			return '';
		}
	};
	const uid = getACF('uid');
	const onStat = (e) => {
      danmuPlayer.setTip(parseInt(e.speed*10)/10 + 'KB/s');
    };
	const createFlvjs = (videoUrl, onStat) => {
		const sourceConfig = {
			isLive: true,
			type: 'flv',
			url: videoUrl
		};
		const playerConfig = {
			enableWorker: false,
			deferLoadAfterSourceOpen: true,
			stashInitialSize: 512*1024,
			enableStashBuffer: true
		};
		const player = flvjs.createPlayer(sourceConfig, playerConfig);
		player.on(flvjs.Events.ERROR, function(e, t) {
			console.error('播放器发生错误：' + e + ' - ' + t);
			player.unload();
		});
	//	player.on(flvjs.Events.STATISTICS_INFO, onStat);
		return player;
	};
	alert(videoUrl1);
//	var player=createFlvjs(videoUrl1, onStat);
//	 player.load();
//      player.play();