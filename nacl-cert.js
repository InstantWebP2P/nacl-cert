// Nacl certification implementation
// Copyright (c) 2014 Tom Zhou<iwebpp@gmail.com>


(function(Export, Nacl, UUID){
	var CERT_VERSION = '1.0';
	
	// Generate cert
	// @param reqdesc: nacl cert description request to sign
	// @param   cakey: nacl ca signature secret key 
	// @param  cacert: ca cert, self-signed 
	// @return cert on success, false on fail
	Export.generate = function(reqdesc, cakey, cacert) {
		// check version
		if (!(reqdesc && reqdesc.version === CERT_VERSION)) {
			console.log('Invalid cert request version');
			return false;
		}

		// check time-to-expire
		if (reqdesc.tte && reqdesc.tte < new Date().getTime()) {
			console.log('Invalid cert time-to-expire, smaller than current time');
			return false;
		}
						
		// check type
		if (reqdesc && 
		    reqdesc.type && 
		   (reqdesc.type.toLowerCase() === 'self' || 
		    reqdesc.type.toLowerCase() === 'ca')) {
			// override CA field
			if (reqdesc.type === 'ca') {
				reqdesc.ca = cacert.desc.ca;

				// check time-to-expire
				if (reqdesc.tte && reqdesc.tte > cacert.desc.tte) {
					console.log('Invalid cert time-to-expire, bigger than CA');
					return false;
				}
			}
			
			// append fields
			reqdesc.signtime = new Date().getTime();
			reqdesc.gid = UUID.v4();

			var cert = {desc: reqdesc};

			// stringify cert.desc
			var descstr = JSON.stringify(cert.desc);
			///console.log('\ngenerate for '+descstr);
			var descbuf = isNodeJS() ? new Uint8Array(new Buffer(descstr, 'utf-8')) :
					                   Nacl.util.decodeUTF8(descstr);

			if (!((cakey &&				  
				   Array.isArray(cakey) &&
				   cakey.length === Nacl.sign.secretKeyLength) ||
				  (cakey &&				  
				   cakey instanceof Uint8Array &&
				   cakey.length === Nacl.sign.secretKeyLength))) {
				console.log('Invalid cert sign secretKey');
				return false;
			}
			var signSecretKey = (cakey instanceof Uint8Array) ? cakey : ArrayToUint8(cakey);

			// sign signature
			var signature = Nacl.sign.detached(descbuf, signSecretKey);
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
	// @return true on success, false on fail
	Export.validate = function(cert, cacert) {
		// check time-to-expire
		if (!(cert && cert.desc && cert.desc.tte > new Date().getTime())) {
			console.log('nacl cert expired');
			return false;
		}

		// check version
		if (!(cert && cert.desc && cert.desc.version.toLowerCase() === CERT_VERSION)) {
			console.log('Invalid cert version');
			return false;
		}

		// check type
		if (cert && 
			cert.desc && 
			cert.desc.type && 
			cert.desc.type.toLowerCase() === 'self') {
            // extract nacl sign publicKey
			if (!(cert && 
				  cert.desc && 
				  cert.desc.publickey && 
				  Array.isArray(cert.desc.publickey) &&
				  cert.desc.publickey.length === Nacl.sign.publicKeyLength)) {
				console.log('Invalid cert sign publicKey');
				return false;
			}
			var signPublicKey = ArrayToUint8(cert.desc.publickey);
			
			// stringify cert.desc
			var descstr = JSON.stringify(cert.desc);
			///console.log('\nvalidate for self-signed:'+descstr);
			var descbuf = isNodeJS() ? new Uint8Array(new Buffer(descstr, 'utf-8')) :
					                   Nacl.util.decodeUTF8(descstr);
			
			// extract signature
			if (!(cert && 
				  cert.sign && 
				  cert.sign.signature && 
				  Array.isArray(cert.sign.signature) &&
				  cert.sign.signature.length === Nacl.sign.signatureLength)) {
				console.log('Invalid signature');
				return false;
			}
			var signature = ArrayToUint8(cert.sign.signature);
			
			// verify signature
			if (!Nacl.sign.detached.verify(descbuf, signature, signPublicKey)) {
				console.log('Verify signature failed');
				return false;
			}
		} else if (cert && 
				   cert.desc && 
				   cert.desc.type && 
				   cert.desc.type.toLowerCase() === 'ca') {
            // check CA cert, MUST be self-signed
			if (!(cacert &&
				  cacert.desc &&
				  cacert.desc.type &&
				  cacert.desc.type.toLowerCase() === 'self')) {
				console.log('CA cert MUST be self-signed');
				return false;
			}
			if (!Export.validate(cacert)) {
				console.log('Invalid CA cert');
				return false;
			}
			
			// check CA name
			if (!(cert.desc.ca && 
				  cacert.desc.ca && 
				 (cert.desc.ca.toLowerCase() === cacert.desc.ca.toLowerCase()))) {
				console.log('CA not matched');
				return false;
			}
			
			// check CA time-to-expire
			if (cert.desc.tte && cert.desc.tte > cacert.desc.tte) {
				console.log('Invalid cert time-to-expire, bigger than CA');
				return false;
			}
			
			// extract nacl sign publicKey
			var casignPublicKey = ArrayToUint8(cacert.desc.publickey);

			// stringify cert.desc
			var cadescstr = JSON.stringify(cert.desc);
			///console.log('\nvalidate for ca-sign:'+cadescstr);
			var cadescbuf = isNodeJS() ? new Uint8Array(new Buffer(cadescstr, 'utf-8')) :
					                     Nacl.util.decodeUTF8(cadescstr);
			
			// extract signature
			if (!(cert && 
				  cert.sign && 
				  cert.sign.signature && 
				  Array.isArray(cert.sign.signature) &&
				  cert.sign.signature.length === Nacl.sign.signatureLength)) {
				console.log('Invalid signature');
				return false;
			}
			var casignature = ArrayToUint8(cert.sign.signature);

			// verify signature
			if (!Nacl.sign.detached.verify(cadescbuf, casignature, casignPublicKey)) {
				console.log('Verify signature failed');
				return false;
			}
		} else  {
			console.log('Invalid cert type');
			return false;
		}

		return true;
	}

	// Check domain name
	Export.checkDomain = function(cert, expectDomain) {
		///console.log('expectDomain:'+expectDomain);
		var ret = false;

		if (cert.desc && cert.desc.names)
			for (var i = 0; i < cert.desc.names.length; i ++)
				// TBD... sub-domain match
				if (expectDomain && expectDomain === cert.desc.names[i]) {
					ret = true;
					break;
				}

		return ret;
	}

	// Check ip
	Export.checkIP = function(cert, expectIP) {
		///console.log('expectIP:'+expectIP);
		var ret = false;

		if (cert.desc && cert.desc.ips)
			for (var i = 0; i < cert.desc.ips.length; i ++)
				if (expectIP && expectIP === cert.desc.ips[i]) {
					ret = true;
					break;
				}

		return ret;
	}

	// Generate self-sgin CA
	// @param cainfo: fill domain name, time-to-expire
	Export.generateCA = function(cainfo) {
		// prepare self-sign reqdesc
		var reqdesc = {};
		reqdesc.version = '1.0';       // fixed
		reqdesc.type    = 'self';      // fixed
		reqdesc.ca      = cainfo.name; // user input
		reqdesc.tte     = cainfo.tte;  // user input

		// generate Sign keypair
		var skp           = Nacl.sign.keyPair();
		reqdesc.publickey = Uint8ToArray(skp.publicKey);

		// generate cert
		var cert = Export.generate(reqdesc, skp.secretKey);

		// return cert with Sign secretKey as JSON array
		return {cert: cert, secretkey: Uint8ToArray(skp.secretKey)};
	}
	
	// default NACL rootCA cert
	Export.rootCA = {};

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
	
	Export.ArrayToUint8  = ArrayToUint8;
	Export.Uint8ToArray  = Uint8ToArray;
})(typeof module  !== 'undefined' ? module.exports                    :(window.naclcert = window.naclcert || {}), 
   typeof require !== 'undefined' ? require('tweetnacl/nacl-fast.js') : window.nacl,
   typeof require !== 'undefined' ? require('node-uuid')              : window.uuid);
		   