// NACL certification implementation
// Copyright (c) 2014 Tom Zhou<iwebpp@gmail.com>


(function(Export, Nacl){
	var CERT_VERSION = '1.0';
	
	// Generate cert
	// @param reqdesc: nacl cert description request to sign
	// @param   cakey: nacl ca signature secret key 
	// @param  cacert: ca cert, self-signed 
	Export.generate = function(reqdesc, cakey, cacert) {
		// check version
		if (!(reqdesc && reqdesc.version === CERT_VERSION)) {
			console.log('Invalid cert request version');
			return false;
		}

		// check type
		if (reqdesc && (reqdesc.type === 'self' || reqdesc.type === 'ca')) {
			// appand fields
			reqdesc.signtime = Date().getTime();
			reqdesc.gid = ''; ///(Uint8ToArray(NACL.randomBytes(16))).join('');

			if (reqdesc.type === 'ca') {
				reqdesc.ca = reqdesc.ca || cacert.desc.names[0];
			}
			
			var cert = {desc: reqdesc};

			// stringify cert.desc
			var descstr = JSON.stringify(cert.desc);
			var descbuf = isNodeJS() ? new Uint8Array(new Buffer(descstr, 'utf-8')) :
					                   NACL.util.decodeUTF8(descstr);

			if (!(cakey &&				  
				  Array.isArray(cakey) &&
				  cakey.length === NACL.sign.secretKeyLength)) {
				console.log('Invalid cert sign secretKey');
				return false;
			}
			var signSecretKey = Array2Uint8(cakey);

			// sign signature
			var signature = NACL.sign.detached(descbuf, signSecretKey);
			if (!signature) {
				console.log('Sign signature failed');
				return false;
			}
			
			// append signature
			cert.sign = {};
			cert.sign.signature = Uint8ToArray(signature);
			
			return cert;
		} else  {
			console.log('Invalid cert type');
			return false;
		}
	}

	// Validate cert
	// @param reqdesc: nacl cert description to sign
	// @param  cacert: ca cert, ignore it in case self-sign 
	Export.validate = function(cert, cacert) {
		// check time-to-expire
		if (!(cert && cert.desc && cert.desc.tte > Date().getTime())) {
			console.log('nacl cert expired');
			return false;
		}

		// check version
		if (!(cert && cert.desc && cert.desc.version === CERT_VERSION)) {
			console.log('Invalid cert version');
			return false;
		}

		// check type
		if (cert && cert.desc && cert.desc.type === 'self') {
            // extract nacl sign publicKey
			if (!(cert && 
				  cert.desc && 
				  cert.desc.publickey && 
				  Array.isArray(cert.desc.publickey) &&
				  cert.desc.publickey.length === NACL.sign.publicKeyLength)) {
				console.log('Invalid cert sign publicKey');
				return false;
			}
			var signPublicKey = Array2Uint8(cert.desc.publickey);
			
			// stringify cert.desc
			var descstr = JSON.stringify(cert.desc);
			var descbuf = isNodeJS() ? new Uint8Array(new Buffer(descstr, 'utf-8')) :
					                   NACL.util.decodeUTF8(descstr);
			
			// extract signature
			if (!(cert && 
				  cert.sign && 
				  cert.sign.signature && 
				  Array.isArray(cert.sign.signature) &&
				  cert.sign.signature.length === NACL.sign.signatureLength)) {
				console.log('Invalid signature');
				return false;
			}
			var signature = Array2Uint8(cert.sign.signature);
			
			// verify signature
			if (!NACL.sign.detached.verify(descbuf, signature, signPublicKey)) {
				console.log('Verify signature failed');
				return false;
			}
		} else if (cert && cert.desc && cert.desc.type === 'ca') {
            // check CA cert, MUST be self-signed
			if (!(cacert &&
				  cacert.type &&
				  cacert.type === 'self')) {
				console.log('CA cert MUST be self-signed');
				return false;
			}
			if (!Export.validate(cacert)) {
				console.log('Invalid CA cert');
				return false;
			}
			
			// extract nacl sign publicKey
			var casignPublicKey = Array2Uint8(cacert.desc.publickey);

			// stringify cert.desc
			var cadescstr = JSON.stringify(cert.desc);
			var cadescbuf = isNodeJS() ? new Uint8Array(new Buffer(cadescstr, 'utf-8')) :
					                     NACL.util.decodeUTF8(cadescstr);
			
			// extract signature
			if (!(cert && 
				  cert.sign && 
				  cert.sign.signature && 
				  Array.isArray(cert.sign.signature) &&
				  cert.sign.signature.length === NACL.sign.signatureLength)) {
				console.log('Invalid signature');
				return false;
			}
			var casignature = Array2Uint8(cert.sign.signature);

			// verify signature
			if (!NACL.sign.detached.verify(cadescbuf, casignature, casignPublicKey)) {
				console.log('Verify signature failed');
				return false;
			}
		} else  {
			console.log('Invalid cert type');
			return false;
		}

		return true;
	}

	// Check domain
	Export.checkDomain = function(cert, expectDomain) {
		var ret = false;

		cert.desc.names.forEach(function(el){
			if (expectDomain === el) 
				ret = true;
		});

		return ret;
	}

	// Check ip
	Export.checkIP = function(cert, expectIP) {
		var ret = false;

		cert.desc.ips.forEach(function(el){
			if (expectIP === el) 
				ret = true;
		});

		return ret;
	}

	// Utils
	function ArrayToUint8(data) {
		if (Array.isArray(data)) {
			var ret = new Uint8Array(data.length);
			ret.set(data);
			return ret;
		} else if (data instanceof Uint8Array) {
			return data
		} else {
			console.log('invalid ArrayToUint8:'+JSON.stringify(data));
			return null;
		}
	}
	function Uint8ToArray(data) {
		if (Array.isArray(data)) {
			return data;
		} else if (data instanceof Uint8Array) {
			return Array.prototype.slice.call(data);
		} else {
			console.log('invalid Uint8ToArray:'+JSON.stringify(data));
			return null;
		}
	}
	function isNodeJS() {
		return (typeof module != 'undefined' && typeof window === 'undefined');
	}

})(typeof module  !== 'undefined' ? module.exports                    :(window.naclcert = window.naclcert || {}), 
   typeof require !== 'undefined' ? require('tweetnacl/nacl-fast.js') : window.nacl);