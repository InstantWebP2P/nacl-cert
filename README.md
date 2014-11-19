nacl-cert
=========

NACL Certification System


### Certification file format as JSON consists of description and signature two parts

* Description object defined as below

  {
      // common part or request part
        "version": string,       // version: '1.0' 
           "type": string,       // type: 'self', 'ca'
          "names": string array, // domain name to ask sign
            "ips": string array, // domain ip to ask sign
            "tte": Date as ms,   // cert live time to expire, ms
      "publickey": array,        // NACL box public key to sign with CA, 
                                 // or signature public key to sign by self
      
      // append fields when sign
            "ca": string       // CA domain name, like iwebpp.com, 
                               // MUST be filled in advance in case self-sign
           "gid": UUID,string, // cert global id: UUID
      "signtime": Date,        // signed time
  }
  
* Signature object defined as below

  {
      signature: array // NACL signature
  }
  
* Entire cert object defined as below

  {
      desc: Description object,
      sign: Signature object
  }
  
  
### Cert request object defined as Common part of Description

  {
     // common part or request part
        "version": string,       // version: '1.0' 
           "type": string,       // type: 'self', 'ca'
          "names": string array, // domain name to ask sign
            "ips": string array, // domain ip to ask sign
            "tte": Date as ms,   // cert live time to expire, ms
      "publickey": array,        // NACL box public key to sign
  }


<br/>
### License
(The MIT License)

Copyright (c) 2014 Tom Zhou(iwebpp@gmail.com)


