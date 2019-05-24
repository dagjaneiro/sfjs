(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.SF = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (global){
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(u,p){var d={},l=d.lib={},s=function(){},t=l.Base={extend:function(a){s.prototype=this;var c=new s;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
r=l.WordArray=t.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=p?c:4*a.length},toString:function(a){return(a||v).stringify(this)},concat:function(a){var c=this.words,e=a.words,j=this.sigBytes;a=a.sigBytes;this.clamp();if(j%4)for(var k=0;k<a;k++)c[j+k>>>2]|=(e[k>>>2]>>>24-8*(k%4)&255)<<24-8*((j+k)%4);else if(65535<e.length)for(k=0;k<a;k+=4)c[j+k>>>2]=e[k>>>2];else c.push.apply(c,e);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=u.ceil(c/4)},clone:function(){var a=t.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],e=0;e<a;e+=4)c.push(4294967296*u.random()|0);return new r.init(c,a)}}),w=d.enc={},v=w.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var e=[],j=0;j<a;j++){var k=c[j>>>2]>>>24-8*(j%4)&255;e.push((k>>>4).toString(16));e.push((k&15).toString(16))}return e.join("")},parse:function(a){for(var c=a.length,e=[],j=0;j<c;j+=2)e[j>>>3]|=parseInt(a.substr(j,
2),16)<<24-4*(j%8);return new r.init(e,c/2)}},b=w.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var e=[],j=0;j<a;j++)e.push(String.fromCharCode(c[j>>>2]>>>24-8*(j%4)&255));return e.join("")},parse:function(a){for(var c=a.length,e=[],j=0;j<c;j++)e[j>>>2]|=(a.charCodeAt(j)&255)<<24-8*(j%4);return new r.init(e,c)}},x=w.Utf8={stringify:function(a){try{return decodeURIComponent(escape(b.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return b.parse(unescape(encodeURIComponent(a)))}},
q=l.BufferedBlockAlgorithm=t.extend({reset:function(){this._data=new r.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=x.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,e=c.words,j=c.sigBytes,k=this.blockSize,b=j/(4*k),b=a?u.ceil(b):u.max((b|0)-this._minBufferSize,0);a=b*k;j=u.min(4*a,j);if(a){for(var q=0;q<a;q+=k)this._doProcessBlock(e,q);q=e.splice(0,a);c.sigBytes-=j}return new r.init(q,j)},clone:function(){var a=t.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});l.Hasher=q.extend({cfg:t.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){q.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,e){return(new a.init(e)).finalize(b)}},_createHmacHelper:function(a){return function(b,e){return(new n.HMAC.init(a,
e)).finalize(b)}}});var n=d.algo={};return d}(Math);
(function(){var u=CryptoJS,p=u.lib.WordArray;u.enc.Base64={stringify:function(d){var l=d.words,p=d.sigBytes,t=this._map;d.clamp();d=[];for(var r=0;r<p;r+=3)for(var w=(l[r>>>2]>>>24-8*(r%4)&255)<<16|(l[r+1>>>2]>>>24-8*((r+1)%4)&255)<<8|l[r+2>>>2]>>>24-8*((r+2)%4)&255,v=0;4>v&&r+0.75*v<p;v++)d.push(t.charAt(w>>>6*(3-v)&63));if(l=t.charAt(64))for(;d.length%4;)d.push(l);return d.join("")},parse:function(d){var l=d.length,s=this._map,t=s.charAt(64);t&&(t=d.indexOf(t),-1!=t&&(l=t));for(var t=[],r=0,w=0;w<
l;w++)if(w%4){var v=s.indexOf(d.charAt(w-1))<<2*(w%4),b=s.indexOf(d.charAt(w))>>>6-2*(w%4);t[r>>>2]|=(v|b)<<24-8*(r%4);r++}return p.create(t,r)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();
(function(u){function p(b,n,a,c,e,j,k){b=b+(n&a|~n&c)+e+k;return(b<<j|b>>>32-j)+n}function d(b,n,a,c,e,j,k){b=b+(n&c|a&~c)+e+k;return(b<<j|b>>>32-j)+n}function l(b,n,a,c,e,j,k){b=b+(n^a^c)+e+k;return(b<<j|b>>>32-j)+n}function s(b,n,a,c,e,j,k){b=b+(a^(n|~c))+e+k;return(b<<j|b>>>32-j)+n}for(var t=CryptoJS,r=t.lib,w=r.WordArray,v=r.Hasher,r=t.algo,b=[],x=0;64>x;x++)b[x]=4294967296*u.abs(u.sin(x+1))|0;r=r.MD5=v.extend({_doReset:function(){this._hash=new w.init([1732584193,4023233417,2562383102,271733878])},
_doProcessBlock:function(q,n){for(var a=0;16>a;a++){var c=n+a,e=q[c];q[c]=(e<<8|e>>>24)&16711935|(e<<24|e>>>8)&4278255360}var a=this._hash.words,c=q[n+0],e=q[n+1],j=q[n+2],k=q[n+3],z=q[n+4],r=q[n+5],t=q[n+6],w=q[n+7],v=q[n+8],A=q[n+9],B=q[n+10],C=q[n+11],u=q[n+12],D=q[n+13],E=q[n+14],x=q[n+15],f=a[0],m=a[1],g=a[2],h=a[3],f=p(f,m,g,h,c,7,b[0]),h=p(h,f,m,g,e,12,b[1]),g=p(g,h,f,m,j,17,b[2]),m=p(m,g,h,f,k,22,b[3]),f=p(f,m,g,h,z,7,b[4]),h=p(h,f,m,g,r,12,b[5]),g=p(g,h,f,m,t,17,b[6]),m=p(m,g,h,f,w,22,b[7]),
f=p(f,m,g,h,v,7,b[8]),h=p(h,f,m,g,A,12,b[9]),g=p(g,h,f,m,B,17,b[10]),m=p(m,g,h,f,C,22,b[11]),f=p(f,m,g,h,u,7,b[12]),h=p(h,f,m,g,D,12,b[13]),g=p(g,h,f,m,E,17,b[14]),m=p(m,g,h,f,x,22,b[15]),f=d(f,m,g,h,e,5,b[16]),h=d(h,f,m,g,t,9,b[17]),g=d(g,h,f,m,C,14,b[18]),m=d(m,g,h,f,c,20,b[19]),f=d(f,m,g,h,r,5,b[20]),h=d(h,f,m,g,B,9,b[21]),g=d(g,h,f,m,x,14,b[22]),m=d(m,g,h,f,z,20,b[23]),f=d(f,m,g,h,A,5,b[24]),h=d(h,f,m,g,E,9,b[25]),g=d(g,h,f,m,k,14,b[26]),m=d(m,g,h,f,v,20,b[27]),f=d(f,m,g,h,D,5,b[28]),h=d(h,f,
m,g,j,9,b[29]),g=d(g,h,f,m,w,14,b[30]),m=d(m,g,h,f,u,20,b[31]),f=l(f,m,g,h,r,4,b[32]),h=l(h,f,m,g,v,11,b[33]),g=l(g,h,f,m,C,16,b[34]),m=l(m,g,h,f,E,23,b[35]),f=l(f,m,g,h,e,4,b[36]),h=l(h,f,m,g,z,11,b[37]),g=l(g,h,f,m,w,16,b[38]),m=l(m,g,h,f,B,23,b[39]),f=l(f,m,g,h,D,4,b[40]),h=l(h,f,m,g,c,11,b[41]),g=l(g,h,f,m,k,16,b[42]),m=l(m,g,h,f,t,23,b[43]),f=l(f,m,g,h,A,4,b[44]),h=l(h,f,m,g,u,11,b[45]),g=l(g,h,f,m,x,16,b[46]),m=l(m,g,h,f,j,23,b[47]),f=s(f,m,g,h,c,6,b[48]),h=s(h,f,m,g,w,10,b[49]),g=s(g,h,f,m,
E,15,b[50]),m=s(m,g,h,f,r,21,b[51]),f=s(f,m,g,h,u,6,b[52]),h=s(h,f,m,g,k,10,b[53]),g=s(g,h,f,m,B,15,b[54]),m=s(m,g,h,f,e,21,b[55]),f=s(f,m,g,h,v,6,b[56]),h=s(h,f,m,g,x,10,b[57]),g=s(g,h,f,m,t,15,b[58]),m=s(m,g,h,f,D,21,b[59]),f=s(f,m,g,h,z,6,b[60]),h=s(h,f,m,g,C,10,b[61]),g=s(g,h,f,m,j,15,b[62]),m=s(m,g,h,f,A,21,b[63]);a[0]=a[0]+f|0;a[1]=a[1]+m|0;a[2]=a[2]+g|0;a[3]=a[3]+h|0},_doFinalize:function(){var b=this._data,n=b.words,a=8*this._nDataBytes,c=8*b.sigBytes;n[c>>>5]|=128<<24-c%32;var e=u.floor(a/
4294967296);n[(c+64>>>9<<4)+15]=(e<<8|e>>>24)&16711935|(e<<24|e>>>8)&4278255360;n[(c+64>>>9<<4)+14]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360;b.sigBytes=4*(n.length+1);this._process();b=this._hash;n=b.words;for(a=0;4>a;a++)c=n[a],n[a]=(c<<8|c>>>24)&16711935|(c<<24|c>>>8)&4278255360;return b},clone:function(){var b=v.clone.call(this);b._hash=this._hash.clone();return b}});t.MD5=v._createHelper(r);t.HmacMD5=v._createHmacHelper(r)})(Math);
(function(){var u=CryptoJS,p=u.lib,d=p.Base,l=p.WordArray,p=u.algo,s=p.EvpKDF=d.extend({cfg:d.extend({keySize:4,hasher:p.MD5,iterations:1}),init:function(d){this.cfg=this.cfg.extend(d)},compute:function(d,r){for(var p=this.cfg,s=p.hasher.create(),b=l.create(),u=b.words,q=p.keySize,p=p.iterations;u.length<q;){n&&s.update(n);var n=s.update(d).finalize(r);s.reset();for(var a=1;a<p;a++)n=s.finalize(n),s.reset();b.concat(n)}b.sigBytes=4*q;return b}});u.EvpKDF=function(d,l,p){return s.create(p).compute(d,
l)}})();
CryptoJS.lib.Cipher||function(u){var p=CryptoJS,d=p.lib,l=d.Base,s=d.WordArray,t=d.BufferedBlockAlgorithm,r=p.enc.Base64,w=p.algo.EvpKDF,v=d.Cipher=t.extend({cfg:l.extend(),createEncryptor:function(e,a){return this.create(this._ENC_XFORM_MODE,e,a)},createDecryptor:function(e,a){return this.create(this._DEC_XFORM_MODE,e,a)},init:function(e,a,b){this.cfg=this.cfg.extend(b);this._xformMode=e;this._key=a;this.reset()},reset:function(){t.reset.call(this);this._doReset()},process:function(e){this._append(e);return this._process()},
finalize:function(e){e&&this._append(e);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(e){return{encrypt:function(b,k,d){return("string"==typeof k?c:a).encrypt(e,b,k,d)},decrypt:function(b,k,d){return("string"==typeof k?c:a).decrypt(e,b,k,d)}}}});d.StreamCipher=v.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var b=p.mode={},x=function(e,a,b){var c=this._iv;c?this._iv=u:c=this._prevBlock;for(var d=0;d<b;d++)e[a+d]^=
c[d]},q=(d.BlockCipherMode=l.extend({createEncryptor:function(e,a){return this.Encryptor.create(e,a)},createDecryptor:function(e,a){return this.Decryptor.create(e,a)},init:function(e,a){this._cipher=e;this._iv=a}})).extend();q.Encryptor=q.extend({processBlock:function(e,a){var b=this._cipher,c=b.blockSize;x.call(this,e,a,c);b.encryptBlock(e,a);this._prevBlock=e.slice(a,a+c)}});q.Decryptor=q.extend({processBlock:function(e,a){var b=this._cipher,c=b.blockSize,d=e.slice(a,a+c);b.decryptBlock(e,a);x.call(this,
e,a,c);this._prevBlock=d}});b=b.CBC=q;q=(p.pad={}).Pkcs7={pad:function(a,b){for(var c=4*b,c=c-a.sigBytes%c,d=c<<24|c<<16|c<<8|c,l=[],n=0;n<c;n+=4)l.push(d);c=s.create(l,c);a.concat(c)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};d.BlockCipher=v.extend({cfg:v.cfg.extend({mode:b,padding:q}),reset:function(){v.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var c=a.createEncryptor;else c=a.createDecryptor,this._minBufferSize=1;this._mode=c.call(a,
this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var n=d.CipherParams=l.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),b=(p.format={}).OpenSSL={stringify:function(a){var b=a.ciphertext;a=a.salt;return(a?s.create([1398893684,
1701076831]).concat(a).concat(b):b).toString(r)},parse:function(a){a=r.parse(a);var b=a.words;if(1398893684==b[0]&&1701076831==b[1]){var c=s.create(b.slice(2,4));b.splice(0,4);a.sigBytes-=16}return n.create({ciphertext:a,salt:c})}},a=d.SerializableCipher=l.extend({cfg:l.extend({format:b}),encrypt:function(a,b,c,d){d=this.cfg.extend(d);var l=a.createEncryptor(c,d);b=l.finalize(b);l=l.cfg;return n.create({ciphertext:b,key:c,iv:l.iv,algorithm:a,mode:l.mode,padding:l.padding,blockSize:a.blockSize,formatter:d.format})},
decrypt:function(a,b,c,d){d=this.cfg.extend(d);b=this._parse(b,d.format);return a.createDecryptor(c,d).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a,this):a}}),p=(p.kdf={}).OpenSSL={execute:function(a,b,c,d){d||(d=s.random(8));a=w.create({keySize:b+c}).compute(a,d);c=s.create(a.words.slice(b),4*c);a.sigBytes=4*b;return n.create({key:a,iv:c,salt:d})}},c=d.PasswordBasedCipher=a.extend({cfg:a.cfg.extend({kdf:p}),encrypt:function(b,c,d,l){l=this.cfg.extend(l);d=l.kdf.execute(d,
b.keySize,b.ivSize);l.iv=d.iv;b=a.encrypt.call(this,b,c,d.key,l);b.mixIn(d);return b},decrypt:function(b,c,d,l){l=this.cfg.extend(l);c=this._parse(c,l.format);d=l.kdf.execute(d,b.keySize,b.ivSize,c.salt);l.iv=d.iv;return a.decrypt.call(this,b,c,d.key,l)}})}();
(function(){for(var u=CryptoJS,p=u.lib.BlockCipher,d=u.algo,l=[],s=[],t=[],r=[],w=[],v=[],b=[],x=[],q=[],n=[],a=[],c=0;256>c;c++)a[c]=128>c?c<<1:c<<1^283;for(var e=0,j=0,c=0;256>c;c++){var k=j^j<<1^j<<2^j<<3^j<<4,k=k>>>8^k&255^99;l[e]=k;s[k]=e;var z=a[e],F=a[z],G=a[F],y=257*a[k]^16843008*k;t[e]=y<<24|y>>>8;r[e]=y<<16|y>>>16;w[e]=y<<8|y>>>24;v[e]=y;y=16843009*G^65537*F^257*z^16843008*e;b[k]=y<<24|y>>>8;x[k]=y<<16|y>>>16;q[k]=y<<8|y>>>24;n[k]=y;e?(e=z^a[a[a[G^z]]],j^=a[a[j]]):e=j=1}var H=[0,1,2,4,8,
16,32,64,128,27,54],d=d.AES=p.extend({_doReset:function(){for(var a=this._key,c=a.words,d=a.sigBytes/4,a=4*((this._nRounds=d+6)+1),e=this._keySchedule=[],j=0;j<a;j++)if(j<d)e[j]=c[j];else{var k=e[j-1];j%d?6<d&&4==j%d&&(k=l[k>>>24]<<24|l[k>>>16&255]<<16|l[k>>>8&255]<<8|l[k&255]):(k=k<<8|k>>>24,k=l[k>>>24]<<24|l[k>>>16&255]<<16|l[k>>>8&255]<<8|l[k&255],k^=H[j/d|0]<<24);e[j]=e[j-d]^k}c=this._invKeySchedule=[];for(d=0;d<a;d++)j=a-d,k=d%4?e[j]:e[j-4],c[d]=4>d||4>=j?k:b[l[k>>>24]]^x[l[k>>>16&255]]^q[l[k>>>
8&255]]^n[l[k&255]]},encryptBlock:function(a,b){this._doCryptBlock(a,b,this._keySchedule,t,r,w,v,l)},decryptBlock:function(a,c){var d=a[c+1];a[c+1]=a[c+3];a[c+3]=d;this._doCryptBlock(a,c,this._invKeySchedule,b,x,q,n,s);d=a[c+1];a[c+1]=a[c+3];a[c+3]=d},_doCryptBlock:function(a,b,c,d,e,j,l,f){for(var m=this._nRounds,g=a[b]^c[0],h=a[b+1]^c[1],k=a[b+2]^c[2],n=a[b+3]^c[3],p=4,r=1;r<m;r++)var q=d[g>>>24]^e[h>>>16&255]^j[k>>>8&255]^l[n&255]^c[p++],s=d[h>>>24]^e[k>>>16&255]^j[n>>>8&255]^l[g&255]^c[p++],t=
d[k>>>24]^e[n>>>16&255]^j[g>>>8&255]^l[h&255]^c[p++],n=d[n>>>24]^e[g>>>16&255]^j[h>>>8&255]^l[k&255]^c[p++],g=q,h=s,k=t;q=(f[g>>>24]<<24|f[h>>>16&255]<<16|f[k>>>8&255]<<8|f[n&255])^c[p++];s=(f[h>>>24]<<24|f[k>>>16&255]<<16|f[n>>>8&255]<<8|f[g&255])^c[p++];t=(f[k>>>24]<<24|f[n>>>16&255]<<16|f[g>>>8&255]<<8|f[h&255])^c[p++];n=(f[n>>>24]<<24|f[g>>>16&255]<<16|f[h>>>8&255]<<8|f[k&255])^c[p++];a[b]=q;a[b+1]=s;a[b+2]=t;a[b+3]=n},keySize:8});u.AES=p._createHelper(d)})();
;/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(h,s){var f={},g=f.lib={},q=function(){},m=g.Base={extend:function(a){q.prototype=this;var c=new q;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
r=g.WordArray=m.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=s?c:4*a.length},toString:function(a){return(a||k).stringify(this)},concat:function(a){var c=this.words,d=a.words,b=this.sigBytes;a=a.sigBytes;this.clamp();if(b%4)for(var e=0;e<a;e++)c[b+e>>>2]|=(d[e>>>2]>>>24-8*(e%4)&255)<<24-8*((b+e)%4);else if(65535<d.length)for(e=0;e<a;e+=4)c[b+e>>>2]=d[e>>>2];else c.push.apply(c,d);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=h.ceil(c/4)},clone:function(){var a=m.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],d=0;d<a;d+=4)c.push(4294967296*h.random()|0);return new r.init(c,a)}}),l=f.enc={},k=l.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++){var e=c[b>>>2]>>>24-8*(b%4)&255;d.push((e>>>4).toString(16));d.push((e&15).toString(16))}return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b+=2)d[b>>>3]|=parseInt(a.substr(b,
2),16)<<24-4*(b%8);return new r.init(d,c/2)}},n=l.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++)d.push(String.fromCharCode(c[b>>>2]>>>24-8*(b%4)&255));return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b++)d[b>>>2]|=(a.charCodeAt(b)&255)<<24-8*(b%4);return new r.init(d,c)}},j=l.Utf8={stringify:function(a){try{return decodeURIComponent(escape(n.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return n.parse(unescape(encodeURIComponent(a)))}},
u=g.BufferedBlockAlgorithm=m.extend({reset:function(){this._data=new r.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=j.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,d=c.words,b=c.sigBytes,e=this.blockSize,f=b/(4*e),f=a?h.ceil(f):h.max((f|0)-this._minBufferSize,0);a=f*e;b=h.min(4*a,b);if(a){for(var g=0;g<a;g+=e)this._doProcessBlock(d,g);g=d.splice(0,a);c.sigBytes-=b}return new r.init(g,b)},clone:function(){var a=m.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});g.Hasher=u.extend({cfg:m.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){u.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,d){return(new a.init(d)).finalize(c)}},_createHmacHelper:function(a){return function(c,d){return(new t.HMAC.init(a,
d)).finalize(c)}}});var t=f.algo={};return f}(Math);
(function(h){for(var s=CryptoJS,f=s.lib,g=f.WordArray,q=f.Hasher,f=s.algo,m=[],r=[],l=function(a){return 4294967296*(a-(a|0))|0},k=2,n=0;64>n;){var j;a:{j=k;for(var u=h.sqrt(j),t=2;t<=u;t++)if(!(j%t)){j=!1;break a}j=!0}j&&(8>n&&(m[n]=l(h.pow(k,0.5))),r[n]=l(h.pow(k,1/3)),n++);k++}var a=[],f=f.SHA256=q.extend({_doReset:function(){this._hash=new g.init(m.slice(0))},_doProcessBlock:function(c,d){for(var b=this._hash.words,e=b[0],f=b[1],g=b[2],j=b[3],h=b[4],m=b[5],n=b[6],q=b[7],p=0;64>p;p++){if(16>p)a[p]=
c[d+p]|0;else{var k=a[p-15],l=a[p-2];a[p]=((k<<25|k>>>7)^(k<<14|k>>>18)^k>>>3)+a[p-7]+((l<<15|l>>>17)^(l<<13|l>>>19)^l>>>10)+a[p-16]}k=q+((h<<26|h>>>6)^(h<<21|h>>>11)^(h<<7|h>>>25))+(h&m^~h&n)+r[p]+a[p];l=((e<<30|e>>>2)^(e<<19|e>>>13)^(e<<10|e>>>22))+(e&f^e&g^f&g);q=n;n=m;m=h;h=j+k|0;j=g;g=f;f=e;e=k+l|0}b[0]=b[0]+e|0;b[1]=b[1]+f|0;b[2]=b[2]+g|0;b[3]=b[3]+j|0;b[4]=b[4]+h|0;b[5]=b[5]+m|0;b[6]=b[6]+n|0;b[7]=b[7]+q|0},_doFinalize:function(){var a=this._data,d=a.words,b=8*this._nDataBytes,e=8*a.sigBytes;
d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=h.floor(b/4294967296);d[(e+64>>>9<<4)+15]=b;a.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var a=q.clone.call(this);a._hash=this._hash.clone();return a}});s.SHA256=q._createHelper(f);s.HmacSHA256=q._createHmacHelper(f)})(Math);
(function(){var h=CryptoJS,s=h.enc.Utf8;h.algo.HMAC=h.lib.Base.extend({init:function(f,g){f=this._hasher=new f.init;"string"==typeof g&&(g=s.parse(g));var h=f.blockSize,m=4*h;g.sigBytes>m&&(g=f.finalize(g));g.clamp();for(var r=this._oKey=g.clone(),l=this._iKey=g.clone(),k=r.words,n=l.words,j=0;j<h;j++)k[j]^=1549556828,n[j]^=909522486;r.sigBytes=l.sigBytes=m;this.reset()},reset:function(){var f=this._hasher;f.reset();f.update(this._iKey)},update:function(f){this._hasher.update(f);return this},finalize:function(f){var g=
this._hasher;f=g.finalize(f);g.reset();return g.finalize(this._oKey.clone().concat(f))}})})();
;/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(a,j){var c={},b=c.lib={},f=function(){},l=b.Base={extend:function(a){f.prototype=this;var d=new f;a&&d.mixIn(a);d.hasOwnProperty("init")||(d.init=function(){d.$super.init.apply(this,arguments)});d.init.prototype=d;d.$super=this;return d},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var d in a)a.hasOwnProperty(d)&&(this[d]=a[d]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
u=b.WordArray=l.extend({init:function(a,d){a=this.words=a||[];this.sigBytes=d!=j?d:4*a.length},toString:function(a){return(a||m).stringify(this)},concat:function(a){var d=this.words,M=a.words,e=this.sigBytes;a=a.sigBytes;this.clamp();if(e%4)for(var b=0;b<a;b++)d[e+b>>>2]|=(M[b>>>2]>>>24-8*(b%4)&255)<<24-8*((e+b)%4);else if(65535<M.length)for(b=0;b<a;b+=4)d[e+b>>>2]=M[b>>>2];else d.push.apply(d,M);this.sigBytes+=a;return this},clamp:function(){var D=this.words,d=this.sigBytes;D[d>>>2]&=4294967295<<
32-8*(d%4);D.length=a.ceil(d/4)},clone:function(){var a=l.clone.call(this);a.words=this.words.slice(0);return a},random:function(D){for(var d=[],b=0;b<D;b+=4)d.push(4294967296*a.random()|0);return new u.init(d,D)}}),k=c.enc={},m=k.Hex={stringify:function(a){var d=a.words;a=a.sigBytes;for(var b=[],e=0;e<a;e++){var c=d[e>>>2]>>>24-8*(e%4)&255;b.push((c>>>4).toString(16));b.push((c&15).toString(16))}return b.join("")},parse:function(a){for(var d=a.length,b=[],e=0;e<d;e+=2)b[e>>>3]|=parseInt(a.substr(e,
2),16)<<24-4*(e%8);return new u.init(b,d/2)}},y=k.Latin1={stringify:function(a){var b=a.words;a=a.sigBytes;for(var c=[],e=0;e<a;e++)c.push(String.fromCharCode(b[e>>>2]>>>24-8*(e%4)&255));return c.join("")},parse:function(a){for(var b=a.length,c=[],e=0;e<b;e++)c[e>>>2]|=(a.charCodeAt(e)&255)<<24-8*(e%4);return new u.init(c,b)}},z=k.Utf8={stringify:function(a){try{return decodeURIComponent(escape(y.stringify(a)))}catch(b){throw Error("Malformed UTF-8 data");}},parse:function(a){return y.parse(unescape(encodeURIComponent(a)))}},
x=b.BufferedBlockAlgorithm=l.extend({reset:function(){this._data=new u.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=z.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(b){var d=this._data,c=d.words,e=d.sigBytes,l=this.blockSize,k=e/(4*l),k=b?a.ceil(k):a.max((k|0)-this._minBufferSize,0);b=k*l;e=a.min(4*b,e);if(b){for(var x=0;x<b;x+=l)this._doProcessBlock(c,x);x=c.splice(0,b);d.sigBytes-=e}return new u.init(x,e)},clone:function(){var a=l.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});b.Hasher=x.extend({cfg:l.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){x.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,c){return(new a.init(c)).finalize(b)}},_createHmacHelper:function(a){return function(b,c){return(new ja.HMAC.init(a,
c)).finalize(b)}}});var ja=c.algo={};return c}(Math);
(function(a){var j=CryptoJS,c=j.lib,b=c.Base,f=c.WordArray,j=j.x64={};j.Word=b.extend({init:function(a,b){this.high=a;this.low=b}});j.WordArray=b.extend({init:function(b,c){b=this.words=b||[];this.sigBytes=c!=a?c:8*b.length},toX32:function(){for(var a=this.words,b=a.length,c=[],m=0;m<b;m++){var y=a[m];c.push(y.high);c.push(y.low)}return f.create(c,this.sigBytes)},clone:function(){for(var a=b.clone.call(this),c=a.words=this.words.slice(0),k=c.length,f=0;f<k;f++)c[f]=c[f].clone();return a}})})();
(function(){function a(){return f.create.apply(f,arguments)}for(var j=CryptoJS,c=j.lib.Hasher,b=j.x64,f=b.Word,l=b.WordArray,b=j.algo,u=[a(1116352408,3609767458),a(1899447441,602891725),a(3049323471,3964484399),a(3921009573,2173295548),a(961987163,4081628472),a(1508970993,3053834265),a(2453635748,2937671579),a(2870763221,3664609560),a(3624381080,2734883394),a(310598401,1164996542),a(607225278,1323610764),a(1426881987,3590304994),a(1925078388,4068182383),a(2162078206,991336113),a(2614888103,633803317),
a(3248222580,3479774868),a(3835390401,2666613458),a(4022224774,944711139),a(264347078,2341262773),a(604807628,2007800933),a(770255983,1495990901),a(1249150122,1856431235),a(1555081692,3175218132),a(1996064986,2198950837),a(2554220882,3999719339),a(2821834349,766784016),a(2952996808,2566594879),a(3210313671,3203337956),a(3336571891,1034457026),a(3584528711,2466948901),a(113926993,3758326383),a(338241895,168717936),a(666307205,1188179964),a(773529912,1546045734),a(1294757372,1522805485),a(1396182291,
2643833823),a(1695183700,2343527390),a(1986661051,1014477480),a(2177026350,1206759142),a(2456956037,344077627),a(2730485921,1290863460),a(2820302411,3158454273),a(3259730800,3505952657),a(3345764771,106217008),a(3516065817,3606008344),a(3600352804,1432725776),a(4094571909,1467031594),a(275423344,851169720),a(430227734,3100823752),a(506948616,1363258195),a(659060556,3750685593),a(883997877,3785050280),a(958139571,3318307427),a(1322822218,3812723403),a(1537002063,2003034995),a(1747873779,3602036899),
a(1955562222,1575990012),a(2024104815,1125592928),a(2227730452,2716904306),a(2361852424,442776044),a(2428436474,593698344),a(2756734187,3733110249),a(3204031479,2999351573),a(3329325298,3815920427),a(3391569614,3928383900),a(3515267271,566280711),a(3940187606,3454069534),a(4118630271,4000239992),a(116418474,1914138554),a(174292421,2731055270),a(289380356,3203993006),a(460393269,320620315),a(685471733,587496836),a(852142971,1086792851),a(1017036298,365543100),a(1126000580,2618297676),a(1288033470,
3409855158),a(1501505948,4234509866),a(1607167915,987167468),a(1816402316,1246189591)],k=[],m=0;80>m;m++)k[m]=a();b=b.SHA512=c.extend({_doReset:function(){this._hash=new l.init([new f.init(1779033703,4089235720),new f.init(3144134277,2227873595),new f.init(1013904242,4271175723),new f.init(2773480762,1595750129),new f.init(1359893119,2917565137),new f.init(2600822924,725511199),new f.init(528734635,4215389547),new f.init(1541459225,327033209)])},_doProcessBlock:function(a,b){for(var c=this._hash.words,
f=c[0],j=c[1],d=c[2],l=c[3],e=c[4],m=c[5],N=c[6],c=c[7],aa=f.high,O=f.low,ba=j.high,P=j.low,ca=d.high,Q=d.low,da=l.high,R=l.low,ea=e.high,S=e.low,fa=m.high,T=m.low,ga=N.high,U=N.low,ha=c.high,V=c.low,r=aa,n=O,G=ba,E=P,H=ca,F=Q,Y=da,I=R,s=ea,p=S,W=fa,J=T,X=ga,K=U,Z=ha,L=V,t=0;80>t;t++){var A=k[t];if(16>t)var q=A.high=a[b+2*t]|0,g=A.low=a[b+2*t+1]|0;else{var q=k[t-15],g=q.high,v=q.low,q=(g>>>1|v<<31)^(g>>>8|v<<24)^g>>>7,v=(v>>>1|g<<31)^(v>>>8|g<<24)^(v>>>7|g<<25),C=k[t-2],g=C.high,h=C.low,C=(g>>>19|
h<<13)^(g<<3|h>>>29)^g>>>6,h=(h>>>19|g<<13)^(h<<3|g>>>29)^(h>>>6|g<<26),g=k[t-7],$=g.high,B=k[t-16],w=B.high,B=B.low,g=v+g.low,q=q+$+(g>>>0<v>>>0?1:0),g=g+h,q=q+C+(g>>>0<h>>>0?1:0),g=g+B,q=q+w+(g>>>0<B>>>0?1:0);A.high=q;A.low=g}var $=s&W^~s&X,B=p&J^~p&K,A=r&G^r&H^G&H,ka=n&E^n&F^E&F,v=(r>>>28|n<<4)^(r<<30|n>>>2)^(r<<25|n>>>7),C=(n>>>28|r<<4)^(n<<30|r>>>2)^(n<<25|r>>>7),h=u[t],la=h.high,ia=h.low,h=L+((p>>>14|s<<18)^(p>>>18|s<<14)^(p<<23|s>>>9)),w=Z+((s>>>14|p<<18)^(s>>>18|p<<14)^(s<<23|p>>>9))+(h>>>
0<L>>>0?1:0),h=h+B,w=w+$+(h>>>0<B>>>0?1:0),h=h+ia,w=w+la+(h>>>0<ia>>>0?1:0),h=h+g,w=w+q+(h>>>0<g>>>0?1:0),g=C+ka,A=v+A+(g>>>0<C>>>0?1:0),Z=X,L=K,X=W,K=J,W=s,J=p,p=I+h|0,s=Y+w+(p>>>0<I>>>0?1:0)|0,Y=H,I=F,H=G,F=E,G=r,E=n,n=h+g|0,r=w+A+(n>>>0<h>>>0?1:0)|0}O=f.low=O+n;f.high=aa+r+(O>>>0<n>>>0?1:0);P=j.low=P+E;j.high=ba+G+(P>>>0<E>>>0?1:0);Q=d.low=Q+F;d.high=ca+H+(Q>>>0<F>>>0?1:0);R=l.low=R+I;l.high=da+Y+(R>>>0<I>>>0?1:0);S=e.low=S+p;e.high=ea+s+(S>>>0<p>>>0?1:0);T=m.low=T+J;m.high=fa+W+(T>>>0<J>>>0?1:
0);U=N.low=U+K;N.high=ga+X+(U>>>0<K>>>0?1:0);V=c.low=V+L;c.high=ha+Z+(V>>>0<L>>>0?1:0)},_doFinalize:function(){var a=this._data,b=a.words,c=8*this._nDataBytes,f=8*a.sigBytes;b[f>>>5]|=128<<24-f%32;b[(f+128>>>10<<5)+30]=Math.floor(c/4294967296);b[(f+128>>>10<<5)+31]=c;a.sigBytes=4*b.length;this._process();return this._hash.toX32()},clone:function(){var a=c.clone.call(this);a._hash=this._hash.clone();return a},blockSize:32});j.SHA512=c._createHelper(b);j.HmacSHA512=c._createHmacHelper(b)})();
(function(){var a=CryptoJS,j=a.enc.Utf8;a.algo.HMAC=a.lib.Base.extend({init:function(a,b){a=this._hasher=new a.init;"string"==typeof b&&(b=j.parse(b));var f=a.blockSize,l=4*f;b.sigBytes>l&&(b=a.finalize(b));b.clamp();for(var u=this._oKey=b.clone(),k=this._iKey=b.clone(),m=u.words,y=k.words,z=0;z<f;z++)m[z]^=1549556828,y[z]^=909522486;u.sigBytes=k.sigBytes=l;this.reset()},reset:function(){var a=this._hasher;a.reset();a.update(this._iKey)},update:function(a){this._hasher.update(a);return this},finalize:function(a){var b=
this._hasher;a=b.finalize(a);b.reset();return b.finalize(this._oKey.clone().concat(a))}})})();
;/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(g,j){var e={},d=e.lib={},m=function(){},n=d.Base={extend:function(a){m.prototype=this;var c=new m;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
q=d.WordArray=n.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=j?c:4*a.length},toString:function(a){return(a||l).stringify(this)},concat:function(a){var c=this.words,p=a.words,f=this.sigBytes;a=a.sigBytes;this.clamp();if(f%4)for(var b=0;b<a;b++)c[f+b>>>2]|=(p[b>>>2]>>>24-8*(b%4)&255)<<24-8*((f+b)%4);else if(65535<p.length)for(b=0;b<a;b+=4)c[f+b>>>2]=p[b>>>2];else c.push.apply(c,p);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=g.ceil(c/4)},clone:function(){var a=n.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],b=0;b<a;b+=4)c.push(4294967296*g.random()|0);return new q.init(c,a)}}),b=e.enc={},l=b.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],f=0;f<a;f++){var d=c[f>>>2]>>>24-8*(f%4)&255;b.push((d>>>4).toString(16));b.push((d&15).toString(16))}return b.join("")},parse:function(a){for(var c=a.length,b=[],f=0;f<c;f+=2)b[f>>>3]|=parseInt(a.substr(f,
2),16)<<24-4*(f%8);return new q.init(b,c/2)}},k=b.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],f=0;f<a;f++)b.push(String.fromCharCode(c[f>>>2]>>>24-8*(f%4)&255));return b.join("")},parse:function(a){for(var c=a.length,b=[],f=0;f<c;f++)b[f>>>2]|=(a.charCodeAt(f)&255)<<24-8*(f%4);return new q.init(b,c)}},h=b.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(b){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},
u=d.BufferedBlockAlgorithm=n.extend({reset:function(){this._data=new q.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=h.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var b=this._data,d=b.words,f=b.sigBytes,l=this.blockSize,e=f/(4*l),e=a?g.ceil(e):g.max((e|0)-this._minBufferSize,0);a=e*l;f=g.min(4*a,f);if(a){for(var h=0;h<a;h+=l)this._doProcessBlock(d,h);h=d.splice(0,a);b.sigBytes-=f}return new q.init(h,f)},clone:function(){var a=n.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});d.Hasher=u.extend({cfg:n.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){u.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,d){return(new a.init(d)).finalize(b)}},_createHmacHelper:function(a){return function(b,d){return(new w.HMAC.init(a,
d)).finalize(b)}}});var w=e.algo={};return e}(Math);
(function(){var g=CryptoJS,j=g.lib,e=j.WordArray,d=j.Hasher,m=[],j=g.algo.SHA1=d.extend({_doReset:function(){this._hash=new e.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(d,e){for(var b=this._hash.words,l=b[0],k=b[1],h=b[2],g=b[3],j=b[4],a=0;80>a;a++){if(16>a)m[a]=d[e+a]|0;else{var c=m[a-3]^m[a-8]^m[a-14]^m[a-16];m[a]=c<<1|c>>>31}c=(l<<5|l>>>27)+j+m[a];c=20>a?c+((k&h|~k&g)+1518500249):40>a?c+((k^h^g)+1859775393):60>a?c+((k&h|k&g|h&g)-1894007588):c+((k^h^
g)-899497514);j=g;g=h;h=k<<30|k>>>2;k=l;l=c}b[0]=b[0]+l|0;b[1]=b[1]+k|0;b[2]=b[2]+h|0;b[3]=b[3]+g|0;b[4]=b[4]+j|0},_doFinalize:function(){var d=this._data,e=d.words,b=8*this._nDataBytes,l=8*d.sigBytes;e[l>>>5]|=128<<24-l%32;e[(l+64>>>9<<4)+14]=Math.floor(b/4294967296);e[(l+64>>>9<<4)+15]=b;d.sigBytes=4*e.length;this._process();return this._hash},clone:function(){var e=d.clone.call(this);e._hash=this._hash.clone();return e}});g.SHA1=d._createHelper(j);g.HmacSHA1=d._createHmacHelper(j)})();
(function(){var g=CryptoJS,j=g.enc.Utf8;g.algo.HMAC=g.lib.Base.extend({init:function(e,d){e=this._hasher=new e.init;"string"==typeof d&&(d=j.parse(d));var g=e.blockSize,n=4*g;d.sigBytes>n&&(d=e.finalize(d));d.clamp();for(var q=this._oKey=d.clone(),b=this._iKey=d.clone(),l=q.words,k=b.words,h=0;h<g;h++)l[h]^=1549556828,k[h]^=909522486;q.sigBytes=b.sigBytes=n;this.reset()},reset:function(){var e=this._hasher;e.reset();e.update(this._iKey)},update:function(e){this._hasher.update(e);return this},finalize:function(e){var d=
this._hasher;e=d.finalize(e);d.reset();return d.finalize(this._oKey.clone().concat(e))}})})();
(function(){var g=CryptoJS,j=g.lib,e=j.Base,d=j.WordArray,j=g.algo,m=j.HMAC,n=j.PBKDF2=e.extend({cfg:e.extend({keySize:4,hasher:j.SHA1,iterations:1}),init:function(d){this.cfg=this.cfg.extend(d)},compute:function(e,b){for(var g=this.cfg,k=m.create(g.hasher,e),h=d.create(),j=d.create([1]),n=h.words,a=j.words,c=g.keySize,g=g.iterations;n.length<c;){var p=k.update(b).finalize(j);k.reset();for(var f=p.words,v=f.length,s=p,t=1;t<g;t++){s=k.finalize(s);k.reset();for(var x=s.words,r=0;r<v;r++)f[r]^=x[r]}h.concat(p);
a[0]++}h.sigBytes=4*c;return h}});g.PBKDF2=function(d,b,e){return n.create(e).compute(d,b)}})();
;/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS=CryptoJS||function(e,m){var p={},j=p.lib={},l=function(){},f=j.Base={extend:function(a){l.prototype=this;var c=new l;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
n=j.WordArray=f.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=m?c:4*a.length},toString:function(a){return(a||h).stringify(this)},concat:function(a){var c=this.words,q=a.words,d=this.sigBytes;a=a.sigBytes;this.clamp();if(d%4)for(var b=0;b<a;b++)c[d+b>>>2]|=(q[b>>>2]>>>24-8*(b%4)&255)<<24-8*((d+b)%4);else if(65535<q.length)for(b=0;b<a;b+=4)c[d+b>>>2]=q[b>>>2];else c.push.apply(c,q);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=e.ceil(c/4)},clone:function(){var a=f.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],b=0;b<a;b+=4)c.push(4294967296*e.random()|0);return new n.init(c,a)}}),b=p.enc={},h=b.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],d=0;d<a;d++){var f=c[d>>>2]>>>24-8*(d%4)&255;b.push((f>>>4).toString(16));b.push((f&15).toString(16))}return b.join("")},parse:function(a){for(var c=a.length,b=[],d=0;d<c;d+=2)b[d>>>3]|=parseInt(a.substr(d,
2),16)<<24-4*(d%8);return new n.init(b,c/2)}},g=b.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],d=0;d<a;d++)b.push(String.fromCharCode(c[d>>>2]>>>24-8*(d%4)&255));return b.join("")},parse:function(a){for(var c=a.length,b=[],d=0;d<c;d++)b[d>>>2]|=(a.charCodeAt(d)&255)<<24-8*(d%4);return new n.init(b,c)}},r=b.Utf8={stringify:function(a){try{return decodeURIComponent(escape(g.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return g.parse(unescape(encodeURIComponent(a)))}},
k=j.BufferedBlockAlgorithm=f.extend({reset:function(){this._data=new n.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=r.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,b=c.words,d=c.sigBytes,f=this.blockSize,h=d/(4*f),h=a?e.ceil(h):e.max((h|0)-this._minBufferSize,0);a=h*f;d=e.min(4*a,d);if(a){for(var g=0;g<a;g+=f)this._doProcessBlock(b,g);g=b.splice(0,a);c.sigBytes-=d}return new n.init(g,d)},clone:function(){var a=f.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});j.Hasher=k.extend({cfg:f.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){k.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,b){return(new a.init(b)).finalize(c)}},_createHmacHelper:function(a){return function(b,f){return(new s.HMAC.init(a,
f)).finalize(b)}}});var s=p.algo={};return p}(Math);
(function(){var e=CryptoJS,m=e.lib,p=m.WordArray,j=m.Hasher,l=[],m=e.algo.SHA1=j.extend({_doReset:function(){this._hash=new p.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(f,n){for(var b=this._hash.words,h=b[0],g=b[1],e=b[2],k=b[3],j=b[4],a=0;80>a;a++){if(16>a)l[a]=f[n+a]|0;else{var c=l[a-3]^l[a-8]^l[a-14]^l[a-16];l[a]=c<<1|c>>>31}c=(h<<5|h>>>27)+j+l[a];c=20>a?c+((g&e|~g&k)+1518500249):40>a?c+((g^e^k)+1859775393):60>a?c+((g&e|g&k|e&k)-1894007588):c+((g^e^
k)-899497514);j=k;k=e;e=g<<30|g>>>2;g=h;h=c}b[0]=b[0]+h|0;b[1]=b[1]+g|0;b[2]=b[2]+e|0;b[3]=b[3]+k|0;b[4]=b[4]+j|0},_doFinalize:function(){var f=this._data,e=f.words,b=8*this._nDataBytes,h=8*f.sigBytes;e[h>>>5]|=128<<24-h%32;e[(h+64>>>9<<4)+14]=Math.floor(b/4294967296);e[(h+64>>>9<<4)+15]=b;f.sigBytes=4*e.length;this._process();return this._hash},clone:function(){var e=j.clone.call(this);e._hash=this._hash.clone();return e}});e.SHA1=j._createHelper(m);e.HmacSHA1=j._createHmacHelper(m)})();
;"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var SFAlertManager = exports.SFAlertManager = function () {
  function SFAlertManager() {
    _classCallCheck(this, SFAlertManager);
  }

  _createClass(SFAlertManager, [{
    key: "alert",
    value: function () {
      var _ref = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(params) {
        return regeneratorRuntime.wrap(function _callee$(_context) {
          while (1) {
            switch (_context.prev = _context.next) {
              case 0:
                return _context.abrupt("return", new Promise(function (resolve, reject) {
                  window.alert(params.text);
                  resolve();
                }));

              case 1:
              case "end":
                return _context.stop();
            }
          }
        }, _callee, this);
      }));

      function alert(_x) {
        return _ref.apply(this, arguments);
      }

      return alert;
    }()
  }, {
    key: "confirm",
    value: function () {
      var _ref2 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee2(params) {
        return regeneratorRuntime.wrap(function _callee2$(_context2) {
          while (1) {
            switch (_context2.prev = _context2.next) {
              case 0:
                return _context2.abrupt("return", new Promise(function (resolve, reject) {
                  if (window.confirm(params.text)) {
                    resolve();
                  } else {
                    reject();
                  }
                }));

              case 1:
              case "end":
                return _context2.stop();
            }
          }
        }, _callee2, this);
      }));

      function confirm(_x2) {
        return _ref2.apply(this, arguments);
      }

      return confirm;
    }()
  }]);

  return SFAlertManager;
}();

;
var SFAuthManager = exports.SFAuthManager = function () {
  function SFAuthManager(storageManager, httpManager, alertManager, timeout) {
    _classCallCheck(this, SFAuthManager);

    SFAuthManager.DidSignOutEvent = "DidSignOutEvent";
    SFAuthManager.WillSignInEvent = "WillSignInEvent";
    SFAuthManager.DidSignInEvent = "DidSignInEvent";

    this.httpManager = httpManager;
    this.storageManager = storageManager;
    this.alertManager = alertManager || new SFAlertManager();
    this.$timeout = timeout || setTimeout.bind(window);

    this.eventHandlers = [];
  }

  _createClass(SFAuthManager, [{
    key: "addEventHandler",
    value: function addEventHandler(handler) {
      this.eventHandlers.push(handler);
      return handler;
    }
  }, {
    key: "removeEventHandler",
    value: function removeEventHandler(handler) {
      _.pull(this.eventHandlers, handler);
    }
  }, {
    key: "notifyEvent",
    value: function notifyEvent(event, data) {
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = undefined;

      try {
        for (var _iterator = this.eventHandlers[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var handler = _step.value;

          handler(event, data || {});
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator.return) {
            _iterator.return();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
    }
  }, {
    key: "saveKeys",
    value: function () {
      var _ref3 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee3(keys) {
        return regeneratorRuntime.wrap(function _callee3$(_context3) {
          while (1) {
            switch (_context3.prev = _context3.next) {
              case 0:
                this._keys = keys;
                _context3.next = 3;
                return this.storageManager.setItem("mk", keys.mk);

              case 3:
                _context3.next = 5;
                return this.storageManager.setItem("ak", keys.ak);

              case 5:
              case "end":
                return _context3.stop();
            }
          }
        }, _callee3, this);
      }));

      function saveKeys(_x3) {
        return _ref3.apply(this, arguments);
      }

      return saveKeys;
    }()
  }, {
    key: "signout",
    value: function () {
      var _ref4 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee4(clearAllData) {
        var _this = this;

        return regeneratorRuntime.wrap(function _callee4$(_context4) {
          while (1) {
            switch (_context4.prev = _context4.next) {
              case 0:
                this._keys = null;
                this._authParams = null;

                if (!clearAllData) {
                  _context4.next = 6;
                  break;
                }

                return _context4.abrupt("return", this.storageManager.clearAllData().then(function () {
                  _this.notifyEvent(SFAuthManager.DidSignOutEvent);
                }));

              case 6:
                this.notifyEvent(SFAuthManager.DidSignOutEvent);

              case 7:
              case "end":
                return _context4.stop();
            }
          }
        }, _callee4, this);
      }));

      function signout(_x4) {
        return _ref4.apply(this, arguments);
      }

      return signout;
    }()
  }, {
    key: "keys",
    value: function () {
      var _ref5 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee5() {
        var mk;
        return regeneratorRuntime.wrap(function _callee5$(_context5) {
          while (1) {
            switch (_context5.prev = _context5.next) {
              case 0:
                if (this._keys) {
                  _context5.next = 11;
                  break;
                }

                _context5.next = 3;
                return this.storageManager.getItem("mk");

              case 3:
                mk = _context5.sent;

                if (mk) {
                  _context5.next = 6;
                  break;
                }

                return _context5.abrupt("return", null);

              case 6:
                _context5.t0 = mk;
                _context5.next = 9;
                return this.storageManager.getItem("ak");

              case 9:
                _context5.t1 = _context5.sent;
                this._keys = {
                  mk: _context5.t0,
                  ak: _context5.t1
                };

              case 11:
                return _context5.abrupt("return", this._keys);

              case 12:
              case "end":
                return _context5.stop();
            }
          }
        }, _callee5, this);
      }));

      function keys() {
        return _ref5.apply(this, arguments);
      }

      return keys;
    }()
  }, {
    key: "getAuthParams",
    value: function () {
      var _ref6 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee6() {
        var data;
        return regeneratorRuntime.wrap(function _callee6$(_context6) {
          while (1) {
            switch (_context6.prev = _context6.next) {
              case 0:
                if (this._authParams) {
                  _context6.next = 5;
                  break;
                }

                _context6.next = 3;
                return this.storageManager.getItem("auth_params");

              case 3:
                data = _context6.sent;

                this._authParams = JSON.parse(data);

              case 5:
                if (!(this._authParams && !this._authParams.version)) {
                  _context6.next = 9;
                  break;
                }

                _context6.next = 8;
                return this.defaultProtocolVersion();

              case 8:
                this._authParams.version = _context6.sent;

              case 9:
                return _context6.abrupt("return", this._authParams);

              case 10:
              case "end":
                return _context6.stop();
            }
          }
        }, _callee6, this);
      }));

      function getAuthParams() {
        return _ref6.apply(this, arguments);
      }

      return getAuthParams;
    }()
  }, {
    key: "defaultProtocolVersion",
    value: function () {
      var _ref7 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee7() {
        var keys;
        return regeneratorRuntime.wrap(function _callee7$(_context7) {
          while (1) {
            switch (_context7.prev = _context7.next) {
              case 0:
                _context7.next = 2;
                return this.keys();

              case 2:
                keys = _context7.sent;

                if (!(keys && keys.ak)) {
                  _context7.next = 7;
                  break;
                }

                return _context7.abrupt("return", "002");

              case 7:
                return _context7.abrupt("return", "001");

              case 8:
              case "end":
                return _context7.stop();
            }
          }
        }, _callee7, this);
      }));

      function defaultProtocolVersion() {
        return _ref7.apply(this, arguments);
      }

      return defaultProtocolVersion;
    }()
  }, {
    key: "protocolVersion",
    value: function () {
      var _ref8 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee8() {
        var authParams;
        return regeneratorRuntime.wrap(function _callee8$(_context8) {
          while (1) {
            switch (_context8.prev = _context8.next) {
              case 0:
                _context8.next = 2;
                return this.getAuthParams();

              case 2:
                authParams = _context8.sent;

                if (!(authParams && authParams.version)) {
                  _context8.next = 5;
                  break;
                }

                return _context8.abrupt("return", authParams.version);

              case 5:
                return _context8.abrupt("return", this.defaultProtocolVersion());

              case 6:
              case "end":
                return _context8.stop();
            }
          }
        }, _callee8, this);
      }));

      function protocolVersion() {
        return _ref8.apply(this, arguments);
      }

      return protocolVersion;
    }()
  }, {
    key: "getAuthParamsForEmail",
    value: function () {
      var _ref9 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee9(url, email, extraParams) {
        var _this2 = this;

        return regeneratorRuntime.wrap(function _callee9$(_context9) {
          while (1) {
            switch (_context9.prev = _context9.next) {
              case 0:
                return _context9.abrupt("return", new Promise(function (resolve, reject) {
                  var requestUrl = url + "/auth/params";
                  _this2.httpManager.getAbsolute(requestUrl, _.merge({ email: email }, extraParams), function (response) {
                    resolve(response);
                  }, function (response) {
                    console.error("Error getting auth params", response);
                    if ((typeof response === "undefined" ? "undefined" : _typeof(response)) !== 'object') {
                      response = { error: { message: "A server error occurred while trying to sign in. Please try again." } };
                    }
                    resolve(response);
                  });
                }));

              case 1:
              case "end":
                return _context9.stop();
            }
          }
        }, _callee9, this);
      }));

      function getAuthParamsForEmail(_x5, _x6, _x7) {
        return _ref9.apply(this, arguments);
      }

      return getAuthParamsForEmail;
    }()
  }, {
    key: "lock",
    value: function lock() {
      this.locked = true;
    }
  }, {
    key: "unlock",
    value: function unlock() {
      this.locked = false;
    }
  }, {
    key: "isLocked",
    value: function isLocked() {
      return this.locked == true;
    }
  }, {
    key: "unlockAndResolve",
    value: function unlockAndResolve(resolve, param) {
      this.unlock();
      resolve(param);
    }
  }, {
    key: "login",
    value: function () {
      var _ref10 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee12(url, email, password, strictSignin, extraParams) {
        var _this3 = this;

        return regeneratorRuntime.wrap(function _callee12$(_context12) {
          while (1) {
            switch (_context12.prev = _context12.next) {
              case 0:
                return _context12.abrupt("return", new Promise(function () {
                  var _ref11 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee11(resolve, reject) {
                    var existingKeys, authParams, message, _message, abort, _message2, minimum, _message3, latestVersion, _message4, keys, requestUrl, params;

                    return regeneratorRuntime.wrap(function _callee11$(_context11) {
                      while (1) {
                        switch (_context11.prev = _context11.next) {
                          case 0:
                            _context11.next = 2;
                            return _this3.keys();

                          case 2:
                            existingKeys = _context11.sent;

                            if (!(existingKeys != null)) {
                              _context11.next = 6;
                              break;
                            }

                            resolve({ error: { message: "Cannot log in because already signed in." } });
                            return _context11.abrupt("return");

                          case 6:
                            if (!_this3.isLocked()) {
                              _context11.next = 9;
                              break;
                            }

                            resolve({ error: { message: "Login already in progress." } });
                            return _context11.abrupt("return");

                          case 9:

                            _this3.lock();

                            _this3.notifyEvent(SFAuthManager.WillSignInEvent);

                            _context11.next = 13;
                            return _this3.getAuthParamsForEmail(url, email, extraParams);

                          case 13:
                            authParams = _context11.sent;


                            // SF3 requires a unique identifier in the auth params
                            authParams.identifier = email;

                            if (!authParams.error) {
                              _context11.next = 18;
                              break;
                            }

                            _this3.unlockAndResolve(resolve, authParams);
                            return _context11.abrupt("return");

                          case 18:
                            if (!(!authParams || !authParams.pw_cost)) {
                              _context11.next = 21;
                              break;
                            }

                            _this3.unlockAndResolve(resolve, { error: { message: "Invalid email or password." } });
                            return _context11.abrupt("return");

                          case 21:
                            if (SFJS.supportedVersions().includes(authParams.version)) {
                              _context11.next = 25;
                              break;
                            }

                            if (SFJS.isVersionNewerThanLibraryVersion(authParams.version)) {
                              // The user has a new account type, but is signing in to an older client.
                              message = "This version of the application does not support your newer account type. Please upgrade to the latest version of Standard Notes to sign in.";
                            } else {
                              // The user has a very old account type, which is no longer supported by this client
                              message = "The protocol version associated with your account is outdated and no longer supported by this application. Please visit standardnotes.org/help/security for more information.";
                            }
                            _this3.unlockAndResolve(resolve, { error: { message: message } });
                            return _context11.abrupt("return");

                          case 25:
                            if (!SFJS.isProtocolVersionOutdated(authParams.version)) {
                              _context11.next = 32;
                              break;
                            }

                            _message = "The encryption version for your account, " + authParams.version + ", is outdated and requires upgrade. You may proceed with login, but are advised to perform a security update using the web or desktop application. Please visit standardnotes.org/help/security for more information.";
                            abort = false;
                            _context11.next = 30;
                            return _this3.alertManager.confirm({
                              title: "Update Needed",
                              text: _message,
                              confirmButtonText: "Sign In"
                            }).catch(function () {
                              _this3.unlockAndResolve(resolve, { error: {} });
                              abort = true;
                            });

                          case 30:
                            if (!abort) {
                              _context11.next = 32;
                              break;
                            }

                            return _context11.abrupt("return");

                          case 32:
                            if (SFJS.supportsPasswordDerivationCost(authParams.pw_cost)) {
                              _context11.next = 36;
                              break;
                            }

                            _message2 = "Your account was created on a platform with higher security capabilities than this browser supports. " + "If we attempted to generate your login keys here, it would take hours. " + "Please use a browser with more up to date security capabilities, like Google Chrome or Firefox, to log in.";

                            _this3.unlockAndResolve(resolve, { error: { message: _message2 } });
                            return _context11.abrupt("return");

                          case 36:
                            minimum = SFJS.costMinimumForVersion(authParams.version);

                            if (!(authParams.pw_cost < minimum)) {
                              _context11.next = 41;
                              break;
                            }

                            _message3 = "Unable to login due to insecure password parameters. Please visit standardnotes.org/help/security for more information.";

                            _this3.unlockAndResolve(resolve, { error: { message: _message3 } });
                            return _context11.abrupt("return");

                          case 41:
                            if (!strictSignin) {
                              _context11.next = 47;
                              break;
                            }

                            // Refuse sign in if authParams.version is anything but the latest version
                            latestVersion = SFJS.version();

                            if (!(authParams.version !== latestVersion)) {
                              _context11.next = 47;
                              break;
                            }

                            _message4 = "Strict sign in refused server sign in parameters. The latest security version is " + latestVersion + ", but your account is reported to have version " + authParams.version + ". If you'd like to proceed with sign in anyway, please disable strict sign in and try again.";

                            _this3.unlockAndResolve(resolve, { error: { message: _message4 } });
                            return _context11.abrupt("return");

                          case 47:
                            _context11.next = 49;
                            return SFJS.crypto.computeEncryptionKeysForUser(password, authParams);

                          case 49:
                            keys = _context11.sent;
                            requestUrl = url + "/auth/sign_in";
                            params = _.merge({ password: keys.pw, email: email }, extraParams);


                            _this3.httpManager.postAbsolute(requestUrl, params, function () {
                              var _ref12 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee10(response) {
                                return regeneratorRuntime.wrap(function _callee10$(_context10) {
                                  while (1) {
                                    switch (_context10.prev = _context10.next) {
                                      case 0:
                                        _context10.next = 2;
                                        return _this3.handleAuthResponse(response, email, url, authParams, keys);

                                      case 2:
                                        _this3.notifyEvent(SFAuthManager.DidSignInEvent);
                                        _this3.$timeout(function () {
                                          return _this3.unlockAndResolve(resolve, response);
                                        });

                                      case 4:
                                      case "end":
                                        return _context10.stop();
                                    }
                                  }
                                }, _callee10, _this3);
                              }));

                              return function (_x15) {
                                return _ref12.apply(this, arguments);
                              };
                            }(), function (response) {
                              console.error("Error logging in", response);
                              if ((typeof response === "undefined" ? "undefined" : _typeof(response)) !== 'object') {
                                response = { error: { message: "A server error occurred while trying to sign in. Please try again." } };
                              }
                              _this3.$timeout(function () {
                                return _this3.unlockAndResolve(resolve, response);
                              });
                            });

                          case 53:
                          case "end":
                            return _context11.stop();
                        }
                      }
                    }, _callee11, _this3);
                  }));

                  return function (_x13, _x14) {
                    return _ref11.apply(this, arguments);
                  };
                }()));

              case 1:
              case "end":
                return _context12.stop();
            }
          }
        }, _callee12, this);
      }));

      function login(_x8, _x9, _x10, _x11, _x12) {
        return _ref10.apply(this, arguments);
      }

      return login;
    }()
  }, {
    key: "register",
    value: function register(url, email, password) {
      var _this4 = this;

      return new Promise(function () {
        var _ref13 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee14(resolve, reject) {
          var results, keys, authParams, requestUrl, params;
          return regeneratorRuntime.wrap(function _callee14$(_context14) {
            while (1) {
              switch (_context14.prev = _context14.next) {
                case 0:
                  if (!_this4.isLocked()) {
                    _context14.next = 3;
                    break;
                  }

                  resolve({ error: { message: "Register already in progress." } });
                  return _context14.abrupt("return");

                case 3:

                  _this4.lock();

                  _context14.next = 6;
                  return SFJS.crypto.generateInitialKeysAndAuthParamsForUser(email, password);

                case 6:
                  results = _context14.sent;
                  keys = results.keys;
                  authParams = results.authParams;
                  requestUrl = url + "/auth";
                  params = _.merge({ password: keys.pw, email: email }, authParams);


                  _this4.httpManager.postAbsolute(requestUrl, params, function () {
                    var _ref14 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee13(response) {
                      return regeneratorRuntime.wrap(function _callee13$(_context13) {
                        while (1) {
                          switch (_context13.prev = _context13.next) {
                            case 0:
                              _context13.next = 2;
                              return _this4.handleAuthResponse(response, email, url, authParams, keys);

                            case 2:
                              _this4.unlockAndResolve(resolve, response);

                            case 3:
                            case "end":
                              return _context13.stop();
                          }
                        }
                      }, _callee13, _this4);
                    }));

                    return function (_x18) {
                      return _ref14.apply(this, arguments);
                    };
                  }(), function (response) {
                    console.error("Registration error", response);
                    if ((typeof response === "undefined" ? "undefined" : _typeof(response)) !== 'object') {
                      response = { error: { message: "A server error occurred while trying to register. Please try again." } };
                    }
                    _this4.unlockAndResolve(resolve, response);
                  });

                case 12:
                case "end":
                  return _context14.stop();
              }
            }
          }, _callee14, _this4);
        }));

        return function (_x16, _x17) {
          return _ref13.apply(this, arguments);
        };
      }());
    }
  }, {
    key: "changePassword",
    value: function () {
      var _ref15 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee17(url, email, current_server_pw, newKeys, newAuthParams) {
        var _this5 = this;

        return regeneratorRuntime.wrap(function _callee17$(_context17) {
          while (1) {
            switch (_context17.prev = _context17.next) {
              case 0:
                return _context17.abrupt("return", new Promise(function () {
                  var _ref16 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee16(resolve, reject) {
                    var newServerPw, requestUrl, params;
                    return regeneratorRuntime.wrap(function _callee16$(_context16) {
                      while (1) {
                        switch (_context16.prev = _context16.next) {
                          case 0:
                            if (!_this5.isLocked()) {
                              _context16.next = 3;
                              break;
                            }

                            resolve({ error: { message: "Change password already in progress." } });
                            return _context16.abrupt("return");

                          case 3:

                            _this5.lock();

                            newServerPw = newKeys.pw;
                            requestUrl = url + "/auth/change_pw";
                            params = _.merge({ new_password: newServerPw, current_password: current_server_pw }, newAuthParams);


                            _this5.httpManager.postAbsolute(requestUrl, params, function () {
                              var _ref17 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee15(response) {
                                return regeneratorRuntime.wrap(function _callee15$(_context15) {
                                  while (1) {
                                    switch (_context15.prev = _context15.next) {
                                      case 0:
                                        _context15.next = 2;
                                        return _this5.handleAuthResponse(response, email, null, newAuthParams, newKeys);

                                      case 2:
                                        _this5.unlockAndResolve(resolve, response);

                                      case 3:
                                      case "end":
                                        return _context15.stop();
                                    }
                                  }
                                }, _callee15, _this5);
                              }));

                              return function (_x26) {
                                return _ref17.apply(this, arguments);
                              };
                            }(), function (response) {
                              if ((typeof response === "undefined" ? "undefined" : _typeof(response)) !== 'object') {
                                response = { error: { message: "Something went wrong while changing your password. Your password was not changed. Please try again." } };
                              }
                              _this5.unlockAndResolve(resolve, response);
                            });

                          case 8:
                          case "end":
                            return _context16.stop();
                        }
                      }
                    }, _callee16, _this5);
                  }));

                  return function (_x24, _x25) {
                    return _ref16.apply(this, arguments);
                  };
                }()));

              case 1:
              case "end":
                return _context17.stop();
            }
          }
        }, _callee17, this);
      }));

      function changePassword(_x19, _x20, _x21, _x22, _x23) {
        return _ref15.apply(this, arguments);
      }

      return changePassword;
    }()
  }, {
    key: "handleAuthResponse",
    value: function () {
      var _ref18 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee18(response, email, url, authParams, keys) {
        return regeneratorRuntime.wrap(function _callee18$(_context18) {
          while (1) {
            switch (_context18.prev = _context18.next) {
              case 0:
                if (!url) {
                  _context18.next = 3;
                  break;
                }

                _context18.next = 3;
                return this.storageManager.setItem("server", url);

              case 3:
                this._authParams = authParams;
                _context18.next = 6;
                return this.storageManager.setItem("auth_params", JSON.stringify(authParams));

              case 6:
                _context18.next = 8;
                return this.storageManager.setItem("jwt", response.token);

              case 8:
                return _context18.abrupt("return", this.saveKeys(keys));

              case 9:
              case "end":
                return _context18.stop();
            }
          }
        }, _callee18, this);
      }));

      function handleAuthResponse(_x27, _x28, _x29, _x30, _x31) {
        return _ref18.apply(this, arguments);
      }

      return handleAuthResponse;
    }()
  }]);

  return SFAuthManager;
}();

;var globalScope = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : null;

var UseAPIVersion = "20190520";

var SFHttpManager = exports.SFHttpManager = function () {
  _createClass(SFHttpManager, null, [{
    key: "getApiVersion",
    value: function getApiVersion() {
      return UseAPIVersion;
    }
  }]);

  function SFHttpManager(timeout, apiVersion) {
    _classCallCheck(this, SFHttpManager);

    // calling callbacks in a $timeout allows UI to update
    this.$timeout = timeout || setTimeout.bind(globalScope);
    this.apiVersion = apiVersion || UseAPIVersion;
  }

  _createClass(SFHttpManager, [{
    key: "setJWTRequestHandler",
    value: function setJWTRequestHandler(handler) {
      this.jwtRequestHandler = handler;
    }
  }, {
    key: "setAuthHeadersForRequest",
    value: function () {
      var _ref19 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee19(request) {
        var token;
        return regeneratorRuntime.wrap(function _callee19$(_context19) {
          while (1) {
            switch (_context19.prev = _context19.next) {
              case 0:
                _context19.next = 2;
                return this.jwtRequestHandler();

              case 2:
                token = _context19.sent;

                if (token) {
                  request.setRequestHeader('Authorization', 'Bearer ' + token);
                }

              case 4:
              case "end":
                return _context19.stop();
            }
          }
        }, _callee19, this);
      }));

      function setAuthHeadersForRequest(_x32) {
        return _ref19.apply(this, arguments);
      }

      return setAuthHeadersForRequest;
    }()
  }, {
    key: "postAbsolute",
    value: function () {
      var _ref20 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee20(url, params, onsuccess, onerror) {
        return regeneratorRuntime.wrap(function _callee20$(_context20) {
          while (1) {
            switch (_context20.prev = _context20.next) {
              case 0:
                return _context20.abrupt("return", this.httpRequest("post", url, params, onsuccess, onerror));

              case 1:
              case "end":
                return _context20.stop();
            }
          }
        }, _callee20, this);
      }));

      function postAbsolute(_x33, _x34, _x35, _x36) {
        return _ref20.apply(this, arguments);
      }

      return postAbsolute;
    }()
  }, {
    key: "patchAbsolute",
    value: function () {
      var _ref21 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee21(url, params, onsuccess, onerror) {
        return regeneratorRuntime.wrap(function _callee21$(_context21) {
          while (1) {
            switch (_context21.prev = _context21.next) {
              case 0:
                return _context21.abrupt("return", this.httpRequest("patch", url, params, onsuccess, onerror));

              case 1:
              case "end":
                return _context21.stop();
            }
          }
        }, _callee21, this);
      }));

      function patchAbsolute(_x37, _x38, _x39, _x40) {
        return _ref21.apply(this, arguments);
      }

      return patchAbsolute;
    }()
  }, {
    key: "getAbsolute",
    value: function () {
      var _ref22 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee22(url, params, onsuccess, onerror) {
        return regeneratorRuntime.wrap(function _callee22$(_context22) {
          while (1) {
            switch (_context22.prev = _context22.next) {
              case 0:
                return _context22.abrupt("return", this.httpRequest("get", url, params, onsuccess, onerror));

              case 1:
              case "end":
                return _context22.stop();
            }
          }
        }, _callee22, this);
      }));

      function getAbsolute(_x41, _x42, _x43, _x44) {
        return _ref22.apply(this, arguments);
      }

      return getAbsolute;
    }()
  }, {
    key: "httpRequest",
    value: function () {
      var _ref23 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee24(verb, url, params, onsuccess, onerror) {
        var _this6 = this;

        return regeneratorRuntime.wrap(function _callee24$(_context24) {
          while (1) {
            switch (_context24.prev = _context24.next) {
              case 0:
                if (!params["api_version"]) {
                  params["api_version"] = this.apiVersion;
                }

                return _context24.abrupt("return", new Promise(function () {
                  var _ref24 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee23(resolve, reject) {
                    var xmlhttp;
                    return regeneratorRuntime.wrap(function _callee23$(_context23) {
                      while (1) {
                        switch (_context23.prev = _context23.next) {
                          case 0:
                            xmlhttp = new XMLHttpRequest();


                            xmlhttp.onreadystatechange = function () {
                              if (xmlhttp.readyState == 4) {
                                var response = xmlhttp.responseText;
                                if (response) {
                                  try {
                                    response = JSON.parse(response);
                                  } catch (e) {}
                                }

                                if (xmlhttp.status >= 200 && xmlhttp.status <= 299) {
                                  _this6.$timeout(function () {
                                    onsuccess(response);
                                    resolve(response);
                                  });
                                } else {
                                  console.error("Request error:", response);
                                  _this6.$timeout(function () {
                                    onerror(response, xmlhttp.status);
                                    reject(response);
                                  });
                                }
                              }
                            };

                            if (verb == "get" && Object.keys(params).length > 0) {
                              url = url + _this6.formatParams(params);
                            }

                            xmlhttp.open(verb, url, true);
                            _context23.next = 6;
                            return _this6.setAuthHeadersForRequest(xmlhttp);

                          case 6:
                            xmlhttp.setRequestHeader('Content-type', 'application/json');

                            if (verb == "post" || verb == "patch") {
                              xmlhttp.send(JSON.stringify(params));
                            } else {
                              xmlhttp.send();
                            }

                          case 8:
                          case "end":
                            return _context23.stop();
                        }
                      }
                    }, _callee23, _this6);
                  }));

                  return function (_x50, _x51) {
                    return _ref24.apply(this, arguments);
                  };
                }()));

              case 2:
              case "end":
                return _context24.stop();
            }
          }
        }, _callee24, this);
      }));

      function httpRequest(_x45, _x46, _x47, _x48, _x49) {
        return _ref23.apply(this, arguments);
      }

      return httpRequest;
    }()
  }, {
    key: "formatParams",
    value: function formatParams(params) {
      return "?" + Object.keys(params).map(function (key) {
        return key + "=" + encodeURIComponent(params[key]);
      }).join("&");
    }
  }]);

  return SFHttpManager;
}();

;
var SFMigrationManager = exports.SFMigrationManager = function () {
  function SFMigrationManager(modelManager, syncManager, storageManager, authManager) {
    var _this7 = this;

    _classCallCheck(this, SFMigrationManager);

    this.modelManager = modelManager;
    this.syncManager = syncManager;
    this.storageManager = storageManager;

    this.completionHandlers = [];

    this.loadMigrations();

    // The syncManager used to dispatch a param called 'initialSync' in the 'sync:completed' event
    // to let us know of the first sync completion after login.
    // however it was removed as it was deemed to be unreliable (returned wrong value when a single sync request repeats on completion for pagination)
    // We'll now use authManager's events instead
    var didReceiveSignInEvent = false;
    var signInHandler = authManager.addEventHandler(function (event) {
      if (event == SFAuthManager.DidSignInEvent) {
        didReceiveSignInEvent = true;
      }
    });

    this.receivedLocalDataEvent = syncManager.initialDataLoaded();

    this.syncManager.addEventHandler(function () {
      var _ref25 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee25(event, data) {
        var dataLoadedEvent, syncCompleteEvent, completedList, _iteratorNormalCompletion2, _didIteratorError2, _iteratorError2, _iterator2, _step2, migrationName, migration;

        return regeneratorRuntime.wrap(function _callee25$(_context25) {
          while (1) {
            switch (_context25.prev = _context25.next) {
              case 0:
                dataLoadedEvent = event == "local-data-loaded";
                syncCompleteEvent = event == "sync:completed";

                if (!(dataLoadedEvent || syncCompleteEvent)) {
                  _context25.next = 40;
                  break;
                }

                if (dataLoadedEvent) {
                  _this7.receivedLocalDataEvent = true;
                } else if (syncCompleteEvent) {
                  _this7.receivedSyncCompletedEvent = true;
                }

                // We want to run pending migrations only after local data has been loaded, and a sync has been completed.

                if (!(_this7.receivedLocalDataEvent && _this7.receivedSyncCompletedEvent)) {
                  _context25.next = 40;
                  break;
                }

                if (!didReceiveSignInEvent) {
                  _context25.next = 39;
                  break;
                }

                // Reset our collected state about sign in
                didReceiveSignInEvent = false;
                authManager.removeEventHandler(signInHandler);

                // If initial online sync, clear any completed migrations that occurred while offline,
                // so they can run again now that we have updated user items. Only clear migrations that
                // don't have `runOnlyOnce` set
                _context25.next = 10;
                return _this7.getCompletedMigrations();

              case 10:
                completedList = _context25.sent.slice();
                _iteratorNormalCompletion2 = true;
                _didIteratorError2 = false;
                _iteratorError2 = undefined;
                _context25.prev = 14;
                _iterator2 = completedList[Symbol.iterator]();

              case 16:
                if (_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done) {
                  _context25.next = 25;
                  break;
                }

                migrationName = _step2.value;
                _context25.next = 20;
                return _this7.migrationForEncodedName(migrationName);

              case 20:
                migration = _context25.sent;

                if (!migration.runOnlyOnce) {
                  _.pull(_this7._completed, migrationName);
                }

              case 22:
                _iteratorNormalCompletion2 = true;
                _context25.next = 16;
                break;

              case 25:
                _context25.next = 31;
                break;

              case 27:
                _context25.prev = 27;
                _context25.t0 = _context25["catch"](14);
                _didIteratorError2 = true;
                _iteratorError2 = _context25.t0;

              case 31:
                _context25.prev = 31;
                _context25.prev = 32;

                if (!_iteratorNormalCompletion2 && _iterator2.return) {
                  _iterator2.return();
                }

              case 34:
                _context25.prev = 34;

                if (!_didIteratorError2) {
                  _context25.next = 37;
                  break;
                }

                throw _iteratorError2;

              case 37:
                return _context25.finish(34);

              case 38:
                return _context25.finish(31);

              case 39:
                _this7.runPendingMigrations();

              case 40:
              case "end":
                return _context25.stop();
            }
          }
        }, _callee25, _this7, [[14, 27, 31, 39], [32,, 34, 38]]);
      }));

      return function (_x52, _x53) {
        return _ref25.apply(this, arguments);
      };
    }());
  }

  _createClass(SFMigrationManager, [{
    key: "addCompletionHandler",
    value: function addCompletionHandler(handler) {
      this.completionHandlers.push(handler);
    }
  }, {
    key: "removeCompletionHandler",
    value: function removeCompletionHandler(handler) {
      _.pull(this.completionHandlers, handler);
    }
  }, {
    key: "migrationForEncodedName",
    value: function () {
      var _ref26 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee26(name) {
        var decoded;
        return regeneratorRuntime.wrap(function _callee26$(_context26) {
          while (1) {
            switch (_context26.prev = _context26.next) {
              case 0:
                _context26.next = 2;
                return this.decode(name);

              case 2:
                decoded = _context26.sent;
                return _context26.abrupt("return", this.migrations.find(function (migration) {
                  return migration.name == decoded;
                }));

              case 4:
              case "end":
                return _context26.stop();
            }
          }
        }, _callee26, this);
      }));

      function migrationForEncodedName(_x54) {
        return _ref26.apply(this, arguments);
      }

      return migrationForEncodedName;
    }()
  }, {
    key: "loadMigrations",
    value: function loadMigrations() {
      this.migrations = this.registeredMigrations();
    }
  }, {
    key: "registeredMigrations",
    value: function registeredMigrations() {
      // Subclasses should return an array of migrations here.
      // Migrations should have a unique `name`, `content_type`,
      // and `handler`, which is a function that accepts an array of matching items to migration.
    }
  }, {
    key: "runPendingMigrations",
    value: function () {
      var _ref27 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee27() {
        var pending, _iteratorNormalCompletion3, _didIteratorError3, _iteratorError3, _iterator3, _step3, migration, _iteratorNormalCompletion4, _didIteratorError4, _iteratorError4, _iterator4, _step4, item, _iteratorNormalCompletion7, _didIteratorError7, _iteratorError7, _iterator7, _step7, _iteratorNormalCompletion5, _didIteratorError5, _iteratorError5, _iterator5, _step5, _iteratorNormalCompletion6, _didIteratorError6, _iteratorError6, _iterator6, _step6, handler;

        return regeneratorRuntime.wrap(function _callee27$(_context27) {
          while (1) {
            switch (_context27.prev = _context27.next) {
              case 0:
                _context27.next = 2;
                return this.getPendingMigrations();

              case 2:
                pending = _context27.sent;


                // run in pre loop, keeping in mind that a migration may be run twice: when offline then again when signing in.
                // we need to reset the items to a new array.
                _iteratorNormalCompletion3 = true;
                _didIteratorError3 = false;
                _iteratorError3 = undefined;
                _context27.prev = 6;
                for (_iterator3 = pending[Symbol.iterator](); !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
                  migration = _step3.value;

                  migration.items = [];
                }

                _context27.next = 14;
                break;

              case 10:
                _context27.prev = 10;
                _context27.t0 = _context27["catch"](6);
                _didIteratorError3 = true;
                _iteratorError3 = _context27.t0;

              case 14:
                _context27.prev = 14;
                _context27.prev = 15;

                if (!_iteratorNormalCompletion3 && _iterator3.return) {
                  _iterator3.return();
                }

              case 17:
                _context27.prev = 17;

                if (!_didIteratorError3) {
                  _context27.next = 20;
                  break;
                }

                throw _iteratorError3;

              case 20:
                return _context27.finish(17);

              case 21:
                return _context27.finish(14);

              case 22:
                _iteratorNormalCompletion4 = true;
                _didIteratorError4 = false;
                _iteratorError4 = undefined;
                _context27.prev = 25;
                _iterator4 = this.modelManager.allNondummyItems[Symbol.iterator]();

              case 27:
                if (_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done) {
                  _context27.next = 51;
                  break;
                }

                item = _step4.value;
                _iteratorNormalCompletion7 = true;
                _didIteratorError7 = false;
                _iteratorError7 = undefined;
                _context27.prev = 32;

                for (_iterator7 = pending[Symbol.iterator](); !(_iteratorNormalCompletion7 = (_step7 = _iterator7.next()).done); _iteratorNormalCompletion7 = true) {
                  migration = _step7.value;

                  if (item.content_type == migration.content_type) {
                    migration.items.push(item);
                  }
                }
                _context27.next = 40;
                break;

              case 36:
                _context27.prev = 36;
                _context27.t1 = _context27["catch"](32);
                _didIteratorError7 = true;
                _iteratorError7 = _context27.t1;

              case 40:
                _context27.prev = 40;
                _context27.prev = 41;

                if (!_iteratorNormalCompletion7 && _iterator7.return) {
                  _iterator7.return();
                }

              case 43:
                _context27.prev = 43;

                if (!_didIteratorError7) {
                  _context27.next = 46;
                  break;
                }

                throw _iteratorError7;

              case 46:
                return _context27.finish(43);

              case 47:
                return _context27.finish(40);

              case 48:
                _iteratorNormalCompletion4 = true;
                _context27.next = 27;
                break;

              case 51:
                _context27.next = 57;
                break;

              case 53:
                _context27.prev = 53;
                _context27.t2 = _context27["catch"](25);
                _didIteratorError4 = true;
                _iteratorError4 = _context27.t2;

              case 57:
                _context27.prev = 57;
                _context27.prev = 58;

                if (!_iteratorNormalCompletion4 && _iterator4.return) {
                  _iterator4.return();
                }

              case 60:
                _context27.prev = 60;

                if (!_didIteratorError4) {
                  _context27.next = 63;
                  break;
                }

                throw _iteratorError4;

              case 63:
                return _context27.finish(60);

              case 64:
                return _context27.finish(57);

              case 65:
                _iteratorNormalCompletion5 = true;
                _didIteratorError5 = false;
                _iteratorError5 = undefined;
                _context27.prev = 68;
                _iterator5 = pending[Symbol.iterator]();

              case 70:
                if (_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done) {
                  _context27.next = 81;
                  break;
                }

                migration = _step5.value;

                if (!(migration.items && migration.items.length > 0 || migration.customHandler)) {
                  _context27.next = 77;
                  break;
                }

                _context27.next = 75;
                return this.runMigration(migration, migration.items);

              case 75:
                _context27.next = 78;
                break;

              case 77:
                this.markMigrationCompleted(migration);

              case 78:
                _iteratorNormalCompletion5 = true;
                _context27.next = 70;
                break;

              case 81:
                _context27.next = 87;
                break;

              case 83:
                _context27.prev = 83;
                _context27.t3 = _context27["catch"](68);
                _didIteratorError5 = true;
                _iteratorError5 = _context27.t3;

              case 87:
                _context27.prev = 87;
                _context27.prev = 88;

                if (!_iteratorNormalCompletion5 && _iterator5.return) {
                  _iterator5.return();
                }

              case 90:
                _context27.prev = 90;

                if (!_didIteratorError5) {
                  _context27.next = 93;
                  break;
                }

                throw _iteratorError5;

              case 93:
                return _context27.finish(90);

              case 94:
                return _context27.finish(87);

              case 95:
                _iteratorNormalCompletion6 = true;
                _didIteratorError6 = false;
                _iteratorError6 = undefined;
                _context27.prev = 98;


                for (_iterator6 = this.completionHandlers[Symbol.iterator](); !(_iteratorNormalCompletion6 = (_step6 = _iterator6.next()).done); _iteratorNormalCompletion6 = true) {
                  handler = _step6.value;

                  handler();
                }
                _context27.next = 106;
                break;

              case 102:
                _context27.prev = 102;
                _context27.t4 = _context27["catch"](98);
                _didIteratorError6 = true;
                _iteratorError6 = _context27.t4;

              case 106:
                _context27.prev = 106;
                _context27.prev = 107;

                if (!_iteratorNormalCompletion6 && _iterator6.return) {
                  _iterator6.return();
                }

              case 109:
                _context27.prev = 109;

                if (!_didIteratorError6) {
                  _context27.next = 112;
                  break;
                }

                throw _iteratorError6;

              case 112:
                return _context27.finish(109);

              case 113:
                return _context27.finish(106);

              case 114:
              case "end":
                return _context27.stop();
            }
          }
        }, _callee27, this, [[6, 10, 14, 22], [15,, 17, 21], [25, 53, 57, 65], [32, 36, 40, 48], [41,, 43, 47], [58,, 60, 64], [68, 83, 87, 95], [88,, 90, 94], [98, 102, 106, 114], [107,, 109, 113]]);
      }));

      function runPendingMigrations() {
        return _ref27.apply(this, arguments);
      }

      return runPendingMigrations;
    }()
  }, {
    key: "encode",
    value: function () {
      var _ref28 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee28(text) {
        return regeneratorRuntime.wrap(function _callee28$(_context28) {
          while (1) {
            switch (_context28.prev = _context28.next) {
              case 0:
                return _context28.abrupt("return", window.btoa(text));

              case 1:
              case "end":
                return _context28.stop();
            }
          }
        }, _callee28, this);
      }));

      function encode(_x55) {
        return _ref28.apply(this, arguments);
      }

      return encode;
    }()
  }, {
    key: "decode",
    value: function () {
      var _ref29 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee29(text) {
        return regeneratorRuntime.wrap(function _callee29$(_context29) {
          while (1) {
            switch (_context29.prev = _context29.next) {
              case 0:
                return _context29.abrupt("return", window.atob(text));

              case 1:
              case "end":
                return _context29.stop();
            }
          }
        }, _callee29, this);
      }));

      function decode(_x56) {
        return _ref29.apply(this, arguments);
      }

      return decode;
    }()
  }, {
    key: "getCompletedMigrations",
    value: function () {
      var _ref30 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee30() {
        var rawCompleted;
        return regeneratorRuntime.wrap(function _callee30$(_context30) {
          while (1) {
            switch (_context30.prev = _context30.next) {
              case 0:
                if (this._completed) {
                  _context30.next = 5;
                  break;
                }

                _context30.next = 3;
                return this.storageManager.getItem("migrations");

              case 3:
                rawCompleted = _context30.sent;

                if (rawCompleted) {
                  this._completed = JSON.parse(rawCompleted);
                } else {
                  this._completed = [];
                }

              case 5:
                return _context30.abrupt("return", this._completed);

              case 6:
              case "end":
                return _context30.stop();
            }
          }
        }, _callee30, this);
      }));

      function getCompletedMigrations() {
        return _ref30.apply(this, arguments);
      }

      return getCompletedMigrations;
    }()
  }, {
    key: "getPendingMigrations",
    value: function () {
      var _ref31 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee31() {
        var completed, pending, _iteratorNormalCompletion8, _didIteratorError8, _iteratorError8, _iterator8, _step8, migration;

        return regeneratorRuntime.wrap(function _callee31$(_context31) {
          while (1) {
            switch (_context31.prev = _context31.next) {
              case 0:
                _context31.next = 2;
                return this.getCompletedMigrations();

              case 2:
                completed = _context31.sent;
                pending = [];
                _iteratorNormalCompletion8 = true;
                _didIteratorError8 = false;
                _iteratorError8 = undefined;
                _context31.prev = 7;
                _iterator8 = this.migrations[Symbol.iterator]();

              case 9:
                if (_iteratorNormalCompletion8 = (_step8 = _iterator8.next()).done) {
                  _context31.next = 22;
                  break;
                }

                migration = _step8.value;
                _context31.t0 = completed;
                _context31.next = 14;
                return this.encode(migration.name);

              case 14:
                _context31.t1 = _context31.sent;
                _context31.t2 = _context31.t0.indexOf.call(_context31.t0, _context31.t1);
                _context31.t3 = -1;

                if (!(_context31.t2 == _context31.t3)) {
                  _context31.next = 19;
                  break;
                }

                pending.push(migration);

              case 19:
                _iteratorNormalCompletion8 = true;
                _context31.next = 9;
                break;

              case 22:
                _context31.next = 28;
                break;

              case 24:
                _context31.prev = 24;
                _context31.t4 = _context31["catch"](7);
                _didIteratorError8 = true;
                _iteratorError8 = _context31.t4;

              case 28:
                _context31.prev = 28;
                _context31.prev = 29;

                if (!_iteratorNormalCompletion8 && _iterator8.return) {
                  _iterator8.return();
                }

              case 31:
                _context31.prev = 31;

                if (!_didIteratorError8) {
                  _context31.next = 34;
                  break;
                }

                throw _iteratorError8;

              case 34:
                return _context31.finish(31);

              case 35:
                return _context31.finish(28);

              case 36:
                return _context31.abrupt("return", pending);

              case 37:
              case "end":
                return _context31.stop();
            }
          }
        }, _callee31, this, [[7, 24, 28, 36], [29,, 31, 35]]);
      }));

      function getPendingMigrations() {
        return _ref31.apply(this, arguments);
      }

      return getPendingMigrations;
    }()
  }, {
    key: "markMigrationCompleted",
    value: function () {
      var _ref32 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee32(migration) {
        var completed;
        return regeneratorRuntime.wrap(function _callee32$(_context32) {
          while (1) {
            switch (_context32.prev = _context32.next) {
              case 0:
                _context32.next = 2;
                return this.getCompletedMigrations();

              case 2:
                completed = _context32.sent;
                _context32.t0 = completed;
                _context32.next = 6;
                return this.encode(migration.name);

              case 6:
                _context32.t1 = _context32.sent;

                _context32.t0.push.call(_context32.t0, _context32.t1);

                this.storageManager.setItem("migrations", JSON.stringify(completed));
                migration.running = false;

              case 10:
              case "end":
                return _context32.stop();
            }
          }
        }, _callee32, this);
      }));

      function markMigrationCompleted(_x57) {
        return _ref32.apply(this, arguments);
      }

      return markMigrationCompleted;
    }()
  }, {
    key: "runMigration",
    value: function () {
      var _ref33 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee33(migration, items) {
        var _this8 = this;

        return regeneratorRuntime.wrap(function _callee33$(_context33) {
          while (1) {
            switch (_context33.prev = _context33.next) {
              case 0:
                if (!migration.running) {
                  _context33.next = 2;
                  break;
                }

                return _context33.abrupt("return");

              case 2:

                console.log("Running migration:", migration.name);

                migration.running = true;

                if (!migration.customHandler) {
                  _context33.next = 8;
                  break;
                }

                return _context33.abrupt("return", migration.customHandler().then(function () {
                  _this8.markMigrationCompleted(migration);
                }));

              case 8:
                return _context33.abrupt("return", migration.handler(items).then(function () {
                  _this8.markMigrationCompleted(migration);
                }));

              case 9:
              case "end":
                return _context33.stop();
            }
          }
        }, _callee33, this);
      }));

      function runMigration(_x58, _x59) {
        return _ref33.apply(this, arguments);
      }

      return runMigration;
    }()
  }]);

  return SFMigrationManager;
}();

;
var SFModelManager = exports.SFModelManager = function () {
  function SFModelManager(timeout) {
    _classCallCheck(this, SFModelManager);

    SFModelManager.MappingSourceRemoteRetrieved = "MappingSourceRemoteRetrieved";
    SFModelManager.MappingSourceRemoteSaved = "MappingSourceRemoteSaved";
    SFModelManager.MappingSourceLocalSaved = "MappingSourceLocalSaved";
    SFModelManager.MappingSourceLocalRetrieved = "MappingSourceLocalRetrieved";
    SFModelManager.MappingSourceLocalDirtied = "MappingSourceLocalDirtied";
    SFModelManager.MappingSourceComponentRetrieved = "MappingSourceComponentRetrieved";
    SFModelManager.MappingSourceDesktopInstalled = "MappingSourceDesktopInstalled"; // When a component is installed by the desktop and some of its values change
    SFModelManager.MappingSourceRemoteActionRetrieved = "MappingSourceRemoteActionRetrieved"; /* aciton-based Extensions like note history */
    SFModelManager.MappingSourceFileImport = "MappingSourceFileImport";

    SFModelManager.isMappingSourceRetrieved = function (source) {
      return [SFModelManager.MappingSourceRemoteRetrieved, SFModelManager.MappingSourceComponentRetrieved, SFModelManager.MappingSourceRemoteActionRetrieved].includes(source);
    };

    this.$timeout = timeout || setTimeout.bind(window);

    this.itemSyncObservers = [];
    this.items = [];
    this.itemsHash = {};
    this.missedReferences = {};
    this.uuidChangeObservers = [];
  }

  _createClass(SFModelManager, [{
    key: "handleSignout",
    value: function handleSignout() {
      this.items.length = 0;
      this.itemsHash = {};
      this.missedReferences = {};
    }
  }, {
    key: "addModelUuidChangeObserver",
    value: function addModelUuidChangeObserver(id, callback) {
      this.uuidChangeObservers.push({ id: id, callback: callback });
    }
  }, {
    key: "notifyObserversOfUuidChange",
    value: function notifyObserversOfUuidChange(oldItem, newItem) {
      var _iteratorNormalCompletion9 = true;
      var _didIteratorError9 = false;
      var _iteratorError9 = undefined;

      try {
        for (var _iterator9 = this.uuidChangeObservers[Symbol.iterator](), _step9; !(_iteratorNormalCompletion9 = (_step9 = _iterator9.next()).done); _iteratorNormalCompletion9 = true) {
          var observer = _step9.value;

          observer.callback(oldItem, newItem);
        }
      } catch (err) {
        _didIteratorError9 = true;
        _iteratorError9 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion9 && _iterator9.return) {
            _iterator9.return();
          }
        } finally {
          if (_didIteratorError9) {
            throw _iteratorError9;
          }
        }
      }
    }
  }, {
    key: "alternateUUIDForItem",
    value: function () {
      var _ref34 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee34(item) {
        var newItem, _iteratorNormalCompletion10, _didIteratorError10, _iteratorError10, _iterator10, _step10, referencingObject;

        return regeneratorRuntime.wrap(function _callee34$(_context34) {
          while (1) {
            switch (_context34.prev = _context34.next) {
              case 0:
                // We need to clone this item and give it a new uuid, then delete item with old uuid from db (you can't modify uuid's in our indexeddb setup)
                newItem = this.createItem(item);
                _context34.next = 3;
                return SFJS.crypto.generateUUID();

              case 3:
                newItem.uuid = _context34.sent;


                // Update uuids of relationships
                newItem.informReferencesOfUUIDChange(item.uuid, newItem.uuid);
                this.informModelsOfUUIDChangeForItem(newItem, item.uuid, newItem.uuid);

                // the new item should inherit the original's relationships
                _iteratorNormalCompletion10 = true;
                _didIteratorError10 = false;
                _iteratorError10 = undefined;
                _context34.prev = 9;
                for (_iterator10 = item.referencingObjects[Symbol.iterator](); !(_iteratorNormalCompletion10 = (_step10 = _iterator10.next()).done); _iteratorNormalCompletion10 = true) {
                  referencingObject = _step10.value;

                  referencingObject.setIsNoLongerBeingReferencedBy(item);
                  item.setIsNoLongerBeingReferencedBy(referencingObject);
                  referencingObject.addItemAsRelationship(newItem);
                }

                _context34.next = 17;
                break;

              case 13:
                _context34.prev = 13;
                _context34.t0 = _context34["catch"](9);
                _didIteratorError10 = true;
                _iteratorError10 = _context34.t0;

              case 17:
                _context34.prev = 17;
                _context34.prev = 18;

                if (!_iteratorNormalCompletion10 && _iterator10.return) {
                  _iterator10.return();
                }

              case 20:
                _context34.prev = 20;

                if (!_didIteratorError10) {
                  _context34.next = 23;
                  break;
                }

                throw _iteratorError10;

              case 23:
                return _context34.finish(20);

              case 24:
                return _context34.finish(17);

              case 25:
                this.setItemsDirty(item.referencingObjects, true);

                // Used to set up referencingObjects for new item (so that other items can now properly reference this new item)
                this.resolveReferencesForItem(newItem);

                console.log(item.uuid, "-->", newItem.uuid);

                // Set to deleted, then run through mapping function so that observers can be notified
                item.deleted = true;
                item.content.references = [];
                // Don't set dirty, because we don't need to sync old item. alternating uuid only occurs in two cases:
                // signing in and merging offline data, or when a uuid-conflict occurs. In both cases, the original item never
                // saves to a server, so doesn't need to be synced.
                // informModelsOfUUIDChangeForItem may set this object to dirty, but we want to undo that here, so that the item gets deleted
                // right away through the mapping function.
                this.setItemDirty(item, false, false, SFModelManager.MappingSourceLocalSaved);
                this.mapResponseItemsToLocalModels([item], SFModelManager.MappingSourceLocalSaved);

                // add new item
                this.addItem(newItem);
                this.setItemDirty(newItem, true, true, SFModelManager.MappingSourceLocalSaved);

                this.notifyObserversOfUuidChange(item, newItem);

                return _context34.abrupt("return", newItem);

              case 36:
              case "end":
                return _context34.stop();
            }
          }
        }, _callee34, this, [[9, 13, 17, 25], [18,, 20, 24]]);
      }));

      function alternateUUIDForItem(_x60) {
        return _ref34.apply(this, arguments);
      }

      return alternateUUIDForItem;
    }()
  }, {
    key: "informModelsOfUUIDChangeForItem",
    value: function informModelsOfUUIDChangeForItem(newItem, oldUUID, newUUID) {
      // some models that only have one-way relationships might be interested to hear that an item has changed its uuid
      // for example, editors have a one way relationship with notes. When a note changes its UUID, it has no way to inform the editor
      // to update its relationships

      var _iteratorNormalCompletion11 = true;
      var _didIteratorError11 = false;
      var _iteratorError11 = undefined;

      try {
        for (var _iterator11 = this.items[Symbol.iterator](), _step11; !(_iteratorNormalCompletion11 = (_step11 = _iterator11.next()).done); _iteratorNormalCompletion11 = true) {
          var model = _step11.value;

          model.potentialItemOfInterestHasChangedItsUUID(newItem, oldUUID, newUUID);
        }
      } catch (err) {
        _didIteratorError11 = true;
        _iteratorError11 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion11 && _iterator11.return) {
            _iterator11.return();
          }
        } finally {
          if (_didIteratorError11) {
            throw _iteratorError11;
          }
        }
      }
    }
  }, {
    key: "didSyncModelsOffline",
    value: function didSyncModelsOffline(items) {
      this.notifySyncObserversOfModels(items, SFModelManager.MappingSourceLocalSaved);
    }
  }, {
    key: "mapResponseItemsToLocalModels",
    value: function mapResponseItemsToLocalModels(items, source, sourceKey) {
      return this.mapResponseItemsToLocalModelsWithOptions({ items: items, source: source, sourceKey: sourceKey });
    }
  }, {
    key: "mapResponseItemsToLocalModelsOmittingFields",
    value: function mapResponseItemsToLocalModelsOmittingFields(items, omitFields, source, sourceKey) {
      return this.mapResponseItemsToLocalModelsWithOptions({ items: items, omitFields: omitFields, source: source, sourceKey: sourceKey });
    }
  }, {
    key: "mapResponseItemsToLocalModelsWithOptions",
    value: function mapResponseItemsToLocalModelsWithOptions(_ref35) {
      var items = _ref35.items,
          omitFields = _ref35.omitFields,
          source = _ref35.source,
          sourceKey = _ref35.sourceKey,
          options = _ref35.options;

      var models = [],
          processedObjects = [],
          modelsToNotifyObserversOf = [];

      // first loop should add and process items
      var _iteratorNormalCompletion12 = true;
      var _didIteratorError12 = false;
      var _iteratorError12 = undefined;

      try {
        for (var _iterator12 = items[Symbol.iterator](), _step12; !(_iteratorNormalCompletion12 = (_step12 = _iterator12.next()).done); _iteratorNormalCompletion12 = true) {
          var json_obj = _step12.value;

          if (!json_obj) {
            continue;
          }

          // content is missing if it has been sucessfullly decrypted but no content
          var isMissingContent = !json_obj.content && !json_obj.errorDecrypting;
          var isCorrupt = !json_obj.content_type || !json_obj.uuid;
          if ((isCorrupt || isMissingContent) && !json_obj.deleted) {
            // An item that is not deleted should never have empty content
            console.error("Server response item is corrupt:", json_obj);
            continue;
          }

          // Lodash's _.omit, which was previously used, seems to cause unexpected behavior
          // when json_obj is an ES6 item class. So we instead manually omit each key.
          if (Array.isArray(omitFields)) {
            var _iteratorNormalCompletion15 = true;
            var _didIteratorError15 = false;
            var _iteratorError15 = undefined;

            try {
              for (var _iterator15 = omitFields[Symbol.iterator](), _step15; !(_iteratorNormalCompletion15 = (_step15 = _iterator15.next()).done); _iteratorNormalCompletion15 = true) {
                var key = _step15.value;

                delete json_obj[key];
              }
            } catch (err) {
              _didIteratorError15 = true;
              _iteratorError15 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion15 && _iterator15.return) {
                  _iterator15.return();
                }
              } finally {
                if (_didIteratorError15) {
                  throw _iteratorError15;
                }
              }
            }
          }

          var item = this.findItem(json_obj.uuid);

          if (item) {
            item.updateFromJSON(json_obj);
            // If an item goes through mapping, it can no longer be a dummy.
            item.dummy = false;
          }

          var contentType = json_obj["content_type"] || item && item.content_type;
          var unknownContentType = this.acceptableContentTypes && !this.acceptableContentTypes.includes(contentType);
          if (unknownContentType) {
            continue;
          }

          var isDirtyItemPendingDelete = false;
          if (json_obj.deleted == true) {
            if (json_obj.dirty) {
              // Item was marked as deleted but not yet synced (in offline scenario)
              // We need to create this item as usual, but just not add it to individual arrays
              // i.e add to this.items but not this.notes (so that it can be retrieved with getDirtyItems)
              isDirtyItemPendingDelete = true;
            } else {
              if (item) {
                modelsToNotifyObserversOf.push(item);
                this.removeItemLocally(item);
              }
              continue;
            }
          }

          if (!item) {
            item = this.createItem(json_obj);
          }

          this.addItem(item, isDirtyItemPendingDelete);

          // Observers do not need to handle items that errored while decrypting.
          if (!item.errorDecrypting) {
            modelsToNotifyObserversOf.push(item);
          }

          models.push(item);
          processedObjects.push(json_obj);
        }

        // second loop should process references
      } catch (err) {
        _didIteratorError12 = true;
        _iteratorError12 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion12 && _iterator12.return) {
            _iterator12.return();
          }
        } finally {
          if (_didIteratorError12) {
            throw _iteratorError12;
          }
        }
      }

      var _iteratorNormalCompletion13 = true;
      var _didIteratorError13 = false;
      var _iteratorError13 = undefined;

      try {
        for (var _iterator13 = processedObjects.entries()[Symbol.iterator](), _step13; !(_iteratorNormalCompletion13 = (_step13 = _iterator13.next()).done); _iteratorNormalCompletion13 = true) {
          var _ref36 = _step13.value;

          var _ref37 = _slicedToArray(_ref36, 2);

          var index = _ref37[0];
          var _json_obj = _ref37[1];

          var model = models[index];
          if (_json_obj.content) {
            this.resolveReferencesForItem(model);
          }

          model.didFinishSyncing();
        }
      } catch (err) {
        _didIteratorError13 = true;
        _iteratorError13 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion13 && _iterator13.return) {
            _iterator13.return();
          }
        } finally {
          if (_didIteratorError13) {
            throw _iteratorError13;
          }
        }
      }

      var missedRefs = this.popMissedReferenceStructsForObjects(processedObjects);

      var _loop = function _loop(ref) {
        var model = models.find(function (candidate) {
          return candidate.uuid == ref.reference_uuid;
        });
        // Model should 100% be defined here, but let's not be too overconfident
        if (model) {
          var itemWaitingForTheValueInThisCurrentLoop = ref.for_item;
          itemWaitingForTheValueInThisCurrentLoop.addItemAsRelationship(model);
        }
      };

      var _iteratorNormalCompletion14 = true;
      var _didIteratorError14 = false;
      var _iteratorError14 = undefined;

      try {
        for (var _iterator14 = missedRefs[Symbol.iterator](), _step14; !(_iteratorNormalCompletion14 = (_step14 = _iterator14.next()).done); _iteratorNormalCompletion14 = true) {
          var ref = _step14.value;

          _loop(ref);
        }
      } catch (err) {
        _didIteratorError14 = true;
        _iteratorError14 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion14 && _iterator14.return) {
            _iterator14.return();
          }
        } finally {
          if (_didIteratorError14) {
            throw _iteratorError14;
          }
        }
      }

      this.notifySyncObserversOfModels(modelsToNotifyObserversOf, source, sourceKey);

      return models;
    }
  }, {
    key: "missedReferenceBuildKey",
    value: function missedReferenceBuildKey(referenceId, objectId) {
      return referenceId + ":" + objectId;
    }
  }, {
    key: "popMissedReferenceStructsForObjects",
    value: function popMissedReferenceStructsForObjects(objects) {
      if (!objects || objects.length == 0) {
        return [];
      }

      var results = [];
      var toDelete = [];
      var uuids = objects.map(function (item) {
        return item.uuid;
      });
      var genericUuidLength = uuids[0].length;

      var keys = Object.keys(this.missedReferences);
      var _iteratorNormalCompletion16 = true;
      var _didIteratorError16 = false;
      var _iteratorError16 = undefined;

      try {
        for (var _iterator16 = keys[Symbol.iterator](), _step16; !(_iteratorNormalCompletion16 = (_step16 = _iterator16.next()).done); _iteratorNormalCompletion16 = true) {
          var candidateKey = _step16.value;

          /*
          We used to do string.split to get at the UUID, but surprisingly,
          the performance of this was about 20x worse then just getting the substring.
           let matches = candidateKey.split(":")[0] == object.uuid;
          */
          var matches = uuids.includes(candidateKey.substring(0, genericUuidLength));
          if (matches) {
            results.push(this.missedReferences[candidateKey]);
            toDelete.push(candidateKey);
          }
        }

        // remove from hash
      } catch (err) {
        _didIteratorError16 = true;
        _iteratorError16 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion16 && _iterator16.return) {
            _iterator16.return();
          }
        } finally {
          if (_didIteratorError16) {
            throw _iteratorError16;
          }
        }
      }

      var _iteratorNormalCompletion17 = true;
      var _didIteratorError17 = false;
      var _iteratorError17 = undefined;

      try {
        for (var _iterator17 = toDelete[Symbol.iterator](), _step17; !(_iteratorNormalCompletion17 = (_step17 = _iterator17.next()).done); _iteratorNormalCompletion17 = true) {
          var key = _step17.value;

          delete this.missedReferences[key];
        }
      } catch (err) {
        _didIteratorError17 = true;
        _iteratorError17 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion17 && _iterator17.return) {
            _iterator17.return();
          }
        } finally {
          if (_didIteratorError17) {
            throw _iteratorError17;
          }
        }
      }

      return results;
    }
  }, {
    key: "resolveReferencesForItem",
    value: function resolveReferencesForItem(item) {
      var markReferencesDirty = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;


      if (item.errorDecrypting) {
        return;
      }

      var contentObject = item.contentObject;

      // If another client removes an item's references, this client won't pick up the removal unless
      // we remove everything not present in the current list of references
      item.updateLocalRelationships();

      if (!contentObject.references) {
        return;
      }

      var references = contentObject.references.slice(); // make copy, references will be modified in array

      var referencesIds = references.map(function (ref) {
        return ref.uuid;
      });
      var includeBlanks = true;
      var referencesObjectResults = this.findItems(referencesIds, includeBlanks);

      var _iteratorNormalCompletion18 = true;
      var _didIteratorError18 = false;
      var _iteratorError18 = undefined;

      try {
        for (var _iterator18 = referencesObjectResults.entries()[Symbol.iterator](), _step18; !(_iteratorNormalCompletion18 = (_step18 = _iterator18.next()).done); _iteratorNormalCompletion18 = true) {
          var _ref38 = _step18.value;

          var _ref39 = _slicedToArray(_ref38, 2);

          var index = _ref39[0];
          var referencedItem = _ref39[1];

          if (referencedItem) {
            item.addItemAsRelationship(referencedItem);
            if (markReferencesDirty) {
              this.setItemDirty(referencedItem, true);
            }
          } else {
            var missingRefId = referencesIds[index];
            // Allows mapper to check when missing reference makes it through the loop,
            // and then runs resolveReferencesForItem again for the original item.
            var mappingKey = this.missedReferenceBuildKey(missingRefId, item.uuid);
            if (!this.missedReferences[mappingKey]) {
              var missedRef = { reference_uuid: missingRefId, for_item: item };
              this.missedReferences[mappingKey] = missedRef;
            }
          }
        }
      } catch (err) {
        _didIteratorError18 = true;
        _iteratorError18 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion18 && _iterator18.return) {
            _iterator18.return();
          }
        } finally {
          if (_didIteratorError18) {
            throw _iteratorError18;
          }
        }
      }
    }

    /* Note that this function is public, and can also be called manually (desktopManager uses it) */

  }, {
    key: "notifySyncObserversOfModels",
    value: function notifySyncObserversOfModels(models, source, sourceKey) {
      var _this9 = this;

      // Make sure `let` is used in the for loops instead of `var`, as we will be using a timeout below.
      var observers = this.itemSyncObservers.sort(function (a, b) {
        // sort by priority
        return a.priority < b.priority ? -1 : 1;
      });

      var _loop2 = function _loop2(observer) {
        var allRelevantItems = observer.types.includes("*") ? models : models.filter(function (item) {
          return observer.types.includes(item.content_type);
        });
        var validItems = [],
            deletedItems = [];
        var _iteratorNormalCompletion20 = true;
        var _didIteratorError20 = false;
        var _iteratorError20 = undefined;

        try {
          for (var _iterator20 = allRelevantItems[Symbol.iterator](), _step20; !(_iteratorNormalCompletion20 = (_step20 = _iterator20.next()).done); _iteratorNormalCompletion20 = true) {
            var item = _step20.value;

            if (item.deleted) {
              deletedItems.push(item);
            } else {
              validItems.push(item);
            }
          }
        } catch (err) {
          _didIteratorError20 = true;
          _iteratorError20 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion20 && _iterator20.return) {
              _iterator20.return();
            }
          } finally {
            if (_didIteratorError20) {
              throw _iteratorError20;
            }
          }
        }

        if (allRelevantItems.length > 0) {
          _this9._callSyncObserverCallbackWithTimeout(observer, allRelevantItems, validItems, deletedItems, source, sourceKey);
        }
      };

      var _iteratorNormalCompletion19 = true;
      var _didIteratorError19 = false;
      var _iteratorError19 = undefined;

      try {
        for (var _iterator19 = observers[Symbol.iterator](), _step19; !(_iteratorNormalCompletion19 = (_step19 = _iterator19.next()).done); _iteratorNormalCompletion19 = true) {
          var observer = _step19.value;

          _loop2(observer);
        }
      } catch (err) {
        _didIteratorError19 = true;
        _iteratorError19 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion19 && _iterator19.return) {
            _iterator19.return();
          }
        } finally {
          if (_didIteratorError19) {
            throw _iteratorError19;
          }
        }
      }
    }

    // When a client sets an item as dirty, it means its values has changed, and everyone should know about it.
    // Particularly extensions. For example, if you edit the title of a note, extensions won't be notified until the save sync completes.
    // With this, they'll be notified immediately.

  }, {
    key: "setItemDirty",
    value: function setItemDirty(item) {
      var dirty = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
      var updateClientDate = arguments[2];
      var source = arguments[3];
      var sourceKey = arguments[4];

      this.setItemsDirty([item], dirty, updateClientDate, source, sourceKey);
    }
  }, {
    key: "setItemsDirty",
    value: function setItemsDirty(items) {
      var dirty = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
      var updateClientDate = arguments[2];
      var source = arguments[3];
      var sourceKey = arguments[4];
      var _iteratorNormalCompletion21 = true;
      var _didIteratorError21 = false;
      var _iteratorError21 = undefined;

      try {
        for (var _iterator21 = items[Symbol.iterator](), _step21; !(_iteratorNormalCompletion21 = (_step21 = _iterator21.next()).done); _iteratorNormalCompletion21 = true) {
          var item = _step21.value;

          item.setDirty(dirty, updateClientDate);
        }
      } catch (err) {
        _didIteratorError21 = true;
        _iteratorError21 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion21 && _iterator21.return) {
            _iterator21.return();
          }
        } finally {
          if (_didIteratorError21) {
            throw _iteratorError21;
          }
        }
      }

      this.notifySyncObserversOfModels(items, source || SFModelManager.MappingSourceLocalDirtied, sourceKey);
    }

    /*
      Rather than running this inline in a for loop, which causes problems and requires all variables to be declared with `let`,
      we'll do it here so it's more explicit and less confusing.
     */

  }, {
    key: "_callSyncObserverCallbackWithTimeout",
    value: function _callSyncObserverCallbackWithTimeout(observer, allRelevantItems, validItems, deletedItems, source, sourceKey) {
      this.$timeout(function () {
        observer.callback(allRelevantItems, validItems, deletedItems, source, sourceKey);
      });
    }
  }, {
    key: "createItem",
    value: function createItem(json_obj) {
      var itemClass = SFModelManager.ContentTypeClassMapping && SFModelManager.ContentTypeClassMapping[json_obj.content_type];
      if (!itemClass) {
        itemClass = SFItem;
      }

      var item = new itemClass(json_obj);
      return item;
    }

    /*
      Be sure itemResponse is a generic Javascript object, and not an Item.
      An Item needs to collapse its properties into its content object before it can be duplicated.
      Note: the reason we need this function is specificallty for the call to resolveReferencesForItem.
      This method creates but does not add the item to the global inventory. It's used by syncManager
      to check if this prospective duplicate item is identical to another item, including the references.
     */

  }, {
    key: "createDuplicateItemFromResponseItem",
    value: function () {
      var _ref40 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee35(itemResponse) {
        var itemResponseCopy, duplicate;
        return regeneratorRuntime.wrap(function _callee35$(_context35) {
          while (1) {
            switch (_context35.prev = _context35.next) {
              case 0:
                if (!(typeof itemResponse.setDirty === 'function')) {
                  _context35.next = 3;
                  break;
                }

                // You should never pass in objects here, as we will modify the itemResponse's uuid below (update: we now make a copy of input value).
                console.error("Attempting to create conflicted copy of non-response item.");
                return _context35.abrupt("return", null);

              case 3:
                // Make a copy so we don't modify input value.
                itemResponseCopy = JSON.parse(JSON.stringify(itemResponse));
                _context35.next = 6;
                return SFJS.crypto.generateUUID();

              case 6:
                itemResponseCopy.uuid = _context35.sent;
                duplicate = this.createItem(itemResponseCopy);
                return _context35.abrupt("return", duplicate);

              case 9:
              case "end":
                return _context35.stop();
            }
          }
        }, _callee35, this);
      }));

      function createDuplicateItemFromResponseItem(_x64) {
        return _ref40.apply(this, arguments);
      }

      return createDuplicateItemFromResponseItem;
    }()
  }, {
    key: "duplicateItemAndAddAsConflict",
    value: function duplicateItemAndAddAsConflict(duplicateOf) {
      return this.duplicateItemWithCustomContentAndAddAsConflict({ content: duplicateOf.content, duplicateOf: duplicateOf });
    }
  }, {
    key: "duplicateItemWithCustomContentAndAddAsConflict",
    value: function duplicateItemWithCustomContentAndAddAsConflict(_ref41) {
      var content = _ref41.content,
          duplicateOf = _ref41.duplicateOf;

      var copy = this.duplicateItemWithCustomContent({ content: content, duplicateOf: duplicateOf });
      this.addDuplicatedItemAsConflict({ duplicate: copy, duplicateOf: duplicateOf });
      return copy;
    }
  }, {
    key: "addDuplicatedItemAsConflict",
    value: function addDuplicatedItemAsConflict(_ref42) {
      var duplicate = _ref42.duplicate,
          duplicateOf = _ref42.duplicateOf;

      this.addDuplicatedItem(duplicate, duplicateOf);
      duplicate.content.conflict_of = duplicateOf.uuid;
    }
  }, {
    key: "duplicateItemWithCustomContent",
    value: function duplicateItemWithCustomContent(_ref43) {
      var content = _ref43.content,
          duplicateOf = _ref43.duplicateOf;

      var copy = new duplicateOf.constructor({ content: content });
      copy.created_at = duplicateOf.created_at;
      copy.content_type = duplicateOf.content_type;
      return copy;
    }
  }, {
    key: "duplicateItemAndAdd",
    value: function duplicateItemAndAdd(item) {
      var copy = this.duplicateItemWithoutAdding(item);
      this.addDuplicatedItem(copy, item);
      return copy;
    }
  }, {
    key: "duplicateItemWithoutAdding",
    value: function duplicateItemWithoutAdding(item) {
      var copy = new item.constructor({ content: item.content });
      copy.created_at = item.created_at;
      copy.content_type = item.content_type;
      return copy;
    }
  }, {
    key: "addDuplicatedItem",
    value: function addDuplicatedItem(duplicate, original) {
      this.addItem(duplicate);
      // the duplicate should inherit the original's relationships
      var _iteratorNormalCompletion22 = true;
      var _didIteratorError22 = false;
      var _iteratorError22 = undefined;

      try {
        for (var _iterator22 = original.referencingObjects[Symbol.iterator](), _step22; !(_iteratorNormalCompletion22 = (_step22 = _iterator22.next()).done); _iteratorNormalCompletion22 = true) {
          var referencingObject = _step22.value;

          referencingObject.addItemAsRelationship(duplicate);
          this.setItemDirty(referencingObject, true);
        }
      } catch (err) {
        _didIteratorError22 = true;
        _iteratorError22 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion22 && _iterator22.return) {
            _iterator22.return();
          }
        } finally {
          if (_didIteratorError22) {
            throw _iteratorError22;
          }
        }
      }

      this.resolveReferencesForItem(duplicate);
      this.setItemDirty(duplicate, true);
    }
  }, {
    key: "addItem",
    value: function addItem(item) {
      var globalOnly = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      this.addItems([item], globalOnly);
    }
  }, {
    key: "addItems",
    value: function addItems(items) {
      var _this10 = this;

      var globalOnly = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      items.forEach(function (item) {
        if (!_this10.itemsHash[item.uuid]) {
          _this10.itemsHash[item.uuid] = item;
          _this10.items.push(item);
        }
      });
    }

    /* Notifies observers when an item has been synced or mapped from a remote response */

  }, {
    key: "addItemSyncObserver",
    value: function addItemSyncObserver(id, types, callback) {
      this.addItemSyncObserverWithPriority({ id: id, types: types, callback: callback, priority: 1 });
    }
  }, {
    key: "addItemSyncObserverWithPriority",
    value: function addItemSyncObserverWithPriority(_ref44) {
      var id = _ref44.id,
          priority = _ref44.priority,
          types = _ref44.types,
          callback = _ref44.callback;

      if (!Array.isArray(types)) {
        types = [types];
      }
      this.itemSyncObservers.push({ id: id, types: types, priority: priority, callback: callback });
    }
  }, {
    key: "removeItemSyncObserver",
    value: function removeItemSyncObserver(id) {
      _.remove(this.itemSyncObservers, _.find(this.itemSyncObservers, { id: id }));
    }
  }, {
    key: "getDirtyItems",
    value: function getDirtyItems() {
      return this.items.filter(function (item) {
        // An item that has an error decrypting can be synced only if it is being deleted.
        // Otherwise, we don't want to send corrupt content up to the server.
        return item.dirty == true && !item.dummy && (!item.errorDecrypting || item.deleted);
      });
    }
  }, {
    key: "clearDirtyItems",
    value: function clearDirtyItems(items) {
      var _iteratorNormalCompletion23 = true;
      var _didIteratorError23 = false;
      var _iteratorError23 = undefined;

      try {
        for (var _iterator23 = items[Symbol.iterator](), _step23; !(_iteratorNormalCompletion23 = (_step23 = _iterator23.next()).done); _iteratorNormalCompletion23 = true) {
          var item = _step23.value;

          item.setDirty(false);
        }
      } catch (err) {
        _didIteratorError23 = true;
        _iteratorError23 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion23 && _iterator23.return) {
            _iterator23.return();
          }
        } finally {
          if (_didIteratorError23) {
            throw _iteratorError23;
          }
        }
      }
    }
  }, {
    key: "removeAndDirtyAllRelationshipsForItem",
    value: function removeAndDirtyAllRelationshipsForItem(item) {
      // Handle direct relationships
      // An item with errorDecrypting will not have valid content field
      if (!item.errorDecrypting) {
        var _iteratorNormalCompletion24 = true;
        var _didIteratorError24 = false;
        var _iteratorError24 = undefined;

        try {
          for (var _iterator24 = item.content.references[Symbol.iterator](), _step24; !(_iteratorNormalCompletion24 = (_step24 = _iterator24.next()).done); _iteratorNormalCompletion24 = true) {
            var reference = _step24.value;

            var relationship = this.findItem(reference.uuid);
            if (relationship) {
              item.removeItemAsRelationship(relationship);
              if (relationship.hasRelationshipWithItem(item)) {
                relationship.removeItemAsRelationship(item);
                this.setItemDirty(relationship, true);
              }
            }
          }
        } catch (err) {
          _didIteratorError24 = true;
          _iteratorError24 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion24 && _iterator24.return) {
              _iterator24.return();
            }
          } finally {
            if (_didIteratorError24) {
              throw _iteratorError24;
            }
          }
        }
      }

      // Handle indirect relationships
      var _iteratorNormalCompletion25 = true;
      var _didIteratorError25 = false;
      var _iteratorError25 = undefined;

      try {
        for (var _iterator25 = item.referencingObjects[Symbol.iterator](), _step25; !(_iteratorNormalCompletion25 = (_step25 = _iterator25.next()).done); _iteratorNormalCompletion25 = true) {
          var object = _step25.value;

          object.removeItemAsRelationship(item);
          this.setItemDirty(object, true);
        }
      } catch (err) {
        _didIteratorError25 = true;
        _iteratorError25 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion25 && _iterator25.return) {
            _iterator25.return();
          }
        } finally {
          if (_didIteratorError25) {
            throw _iteratorError25;
          }
        }
      }

      item.referencingObjects = [];
    }

    /* Used when changing encryption key */

  }, {
    key: "setAllItemsDirty",
    value: function setAllItemsDirty() {
      var relevantItems = this.allItems;
      this.setItemsDirty(relevantItems, true);
    }
  }, {
    key: "setItemToBeDeleted",
    value: function setItemToBeDeleted(item) {
      item.deleted = true;

      if (!item.dummy) {
        this.setItemDirty(item, true);
      }

      this.removeAndDirtyAllRelationshipsForItem(item);
    }
  }, {
    key: "removeItemLocally",
    value: function () {
      var _ref45 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee36(item) {
        return regeneratorRuntime.wrap(function _callee36$(_context36) {
          while (1) {
            switch (_context36.prev = _context36.next) {
              case 0:
                _.remove(this.items, { uuid: item.uuid });

                delete this.itemsHash[item.uuid];

                item.isBeingRemovedLocally();

              case 3:
              case "end":
                return _context36.stop();
            }
          }
        }, _callee36, this);
      }));

      function removeItemLocally(_x67) {
        return _ref45.apply(this, arguments);
      }

      return removeItemLocally;
    }()

    /* Searching */

  }, {
    key: "allItemsMatchingTypes",
    value: function allItemsMatchingTypes(contentTypes) {
      return this.allItems.filter(function (item) {
        return (_.includes(contentTypes, item.content_type) || _.includes(contentTypes, "*")) && !item.dummy;
      });
    }
  }, {
    key: "invalidItems",
    value: function invalidItems() {
      return this.allItems.filter(function (item) {
        return item.errorDecrypting;
      });
    }
  }, {
    key: "validItemsForContentType",
    value: function validItemsForContentType(contentType) {
      return this.allItems.filter(function (item) {
        return item.content_type == contentType && !item.errorDecrypting;
      });
    }
  }, {
    key: "findItem",
    value: function findItem(itemId) {
      return this.itemsHash[itemId];
    }
  }, {
    key: "findItems",
    value: function findItems(ids) {
      var includeBlanks = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      var results = [];
      var _iteratorNormalCompletion26 = true;
      var _didIteratorError26 = false;
      var _iteratorError26 = undefined;

      try {
        for (var _iterator26 = ids[Symbol.iterator](), _step26; !(_iteratorNormalCompletion26 = (_step26 = _iterator26.next()).done); _iteratorNormalCompletion26 = true) {
          var id = _step26.value;

          var item = this.itemsHash[id];
          if (item || includeBlanks) {
            results.push(item);
          }
        }
      } catch (err) {
        _didIteratorError26 = true;
        _iteratorError26 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion26 && _iterator26.return) {
            _iterator26.return();
          }
        } finally {
          if (_didIteratorError26) {
            throw _iteratorError26;
          }
        }
      }

      return results;
    }
  }, {
    key: "itemsMatchingPredicate",
    value: function itemsMatchingPredicate(predicate) {
      return this.itemsMatchingPredicates([predicate]);
    }
  }, {
    key: "itemsMatchingPredicates",
    value: function itemsMatchingPredicates(predicates) {
      return this.filterItemsWithPredicates(this.allItems, predicates);
    }
  }, {
    key: "filterItemsWithPredicates",
    value: function filterItemsWithPredicates(items, predicates) {
      var results = items.filter(function (item) {
        var _iteratorNormalCompletion27 = true;
        var _didIteratorError27 = false;
        var _iteratorError27 = undefined;

        try {
          for (var _iterator27 = predicates[Symbol.iterator](), _step27; !(_iteratorNormalCompletion27 = (_step27 = _iterator27.next()).done); _iteratorNormalCompletion27 = true) {
            var predicate = _step27.value;

            if (!item.satisfiesPredicate(predicate)) {
              return false;
            }
          }
        } catch (err) {
          _didIteratorError27 = true;
          _iteratorError27 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion27 && _iterator27.return) {
              _iterator27.return();
            }
          } finally {
            if (_didIteratorError27) {
              throw _iteratorError27;
            }
          }
        }

        return true;
      });

      return results;
    }

    /*
    Archives
    */

  }, {
    key: "importItems",
    value: function () {
      var _ref46 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee37(externalItems) {
        var itemsToBeMapped, localValues, _iteratorNormalCompletion28, _didIteratorError28, _iteratorError28, _iterator28, _step28, itemData, localItem, frozenValue, _iteratorNormalCompletion29, _didIteratorError29, _iteratorError29, _iterator29, _step29, _itemData, _localValues$_itemDat, itemRef, duplicate, items, _iteratorNormalCompletion30, _didIteratorError30, _iteratorError30, _iterator30, _step30, item;

        return regeneratorRuntime.wrap(function _callee37$(_context37) {
          while (1) {
            switch (_context37.prev = _context37.next) {
              case 0:
                itemsToBeMapped = [];
                // Get local values before doing any processing. This way, if a note change below modifies a tag,
                // and the tag is going to be iterated on in the same loop, then we don't want this change to be compared
                // to the local value.

                localValues = {};
                _iteratorNormalCompletion28 = true;
                _didIteratorError28 = false;
                _iteratorError28 = undefined;
                _context37.prev = 5;
                _iterator28 = externalItems[Symbol.iterator]();

              case 7:
                if (_iteratorNormalCompletion28 = (_step28 = _iterator28.next()).done) {
                  _context37.next = 18;
                  break;
                }

                itemData = _step28.value;
                localItem = this.findItem(itemData.uuid);

                if (localItem) {
                  _context37.next = 13;
                  break;
                }

                localValues[itemData.uuid] = {};
                return _context37.abrupt("continue", 15);

              case 13:
                frozenValue = this.duplicateItemWithoutAdding(localItem);

                localValues[itemData.uuid] = { frozenValue: frozenValue, itemRef: localItem };

              case 15:
                _iteratorNormalCompletion28 = true;
                _context37.next = 7;
                break;

              case 18:
                _context37.next = 24;
                break;

              case 20:
                _context37.prev = 20;
                _context37.t0 = _context37["catch"](5);
                _didIteratorError28 = true;
                _iteratorError28 = _context37.t0;

              case 24:
                _context37.prev = 24;
                _context37.prev = 25;

                if (!_iteratorNormalCompletion28 && _iterator28.return) {
                  _iterator28.return();
                }

              case 27:
                _context37.prev = 27;

                if (!_didIteratorError28) {
                  _context37.next = 30;
                  break;
                }

                throw _iteratorError28;

              case 30:
                return _context37.finish(27);

              case 31:
                return _context37.finish(24);

              case 32:
                _iteratorNormalCompletion29 = true;
                _didIteratorError29 = false;
                _iteratorError29 = undefined;
                _context37.prev = 35;
                _iterator29 = externalItems[Symbol.iterator]();

              case 37:
                if (_iteratorNormalCompletion29 = (_step29 = _iterator29.next()).done) {
                  _context37.next = 52;
                  break;
                }

                _itemData = _step29.value;
                _localValues$_itemDat = localValues[_itemData.uuid], frozenValue = _localValues$_itemDat.frozenValue, itemRef = _localValues$_itemDat.itemRef;

                if (!(frozenValue && !itemRef.errorDecrypting)) {
                  _context37.next = 47;
                  break;
                }

                _context37.next = 43;
                return this.createDuplicateItemFromResponseItem(_itemData);

              case 43:
                duplicate = _context37.sent;

                if (!_itemData.deleted && !frozenValue.isItemContentEqualWith(duplicate)) {
                  // Data differs
                  this.addDuplicatedItemAsConflict({ duplicate: duplicate, duplicateOf: itemRef });
                  itemsToBeMapped.push(duplicate);
                }
                _context37.next = 49;
                break;

              case 47:
                // it doesn't exist, push it into items to be mapped
                itemsToBeMapped.push(_itemData);
                if (itemRef && itemRef.errorDecrypting) {
                  itemRef.errorDecrypting = false;
                }

              case 49:
                _iteratorNormalCompletion29 = true;
                _context37.next = 37;
                break;

              case 52:
                _context37.next = 58;
                break;

              case 54:
                _context37.prev = 54;
                _context37.t1 = _context37["catch"](35);
                _didIteratorError29 = true;
                _iteratorError29 = _context37.t1;

              case 58:
                _context37.prev = 58;
                _context37.prev = 59;

                if (!_iteratorNormalCompletion29 && _iterator29.return) {
                  _iterator29.return();
                }

              case 61:
                _context37.prev = 61;

                if (!_didIteratorError29) {
                  _context37.next = 64;
                  break;
                }

                throw _iteratorError29;

              case 64:
                return _context37.finish(61);

              case 65:
                return _context37.finish(58);

              case 66:
                items = this.mapResponseItemsToLocalModels(itemsToBeMapped, SFModelManager.MappingSourceFileImport);
                _iteratorNormalCompletion30 = true;
                _didIteratorError30 = false;
                _iteratorError30 = undefined;
                _context37.prev = 70;

                for (_iterator30 = items[Symbol.iterator](); !(_iteratorNormalCompletion30 = (_step30 = _iterator30.next()).done); _iteratorNormalCompletion30 = true) {
                  item = _step30.value;

                  this.setItemDirty(item, true, true);
                  item.deleted = false;
                }

                _context37.next = 78;
                break;

              case 74:
                _context37.prev = 74;
                _context37.t2 = _context37["catch"](70);
                _didIteratorError30 = true;
                _iteratorError30 = _context37.t2;

              case 78:
                _context37.prev = 78;
                _context37.prev = 79;

                if (!_iteratorNormalCompletion30 && _iterator30.return) {
                  _iterator30.return();
                }

              case 81:
                _context37.prev = 81;

                if (!_didIteratorError30) {
                  _context37.next = 84;
                  break;
                }

                throw _iteratorError30;

              case 84:
                return _context37.finish(81);

              case 85:
                return _context37.finish(78);

              case 86:
                return _context37.abrupt("return", items);

              case 87:
              case "end":
                return _context37.stop();
            }
          }
        }, _callee37, this, [[5, 20, 24, 32], [25,, 27, 31], [35, 54, 58, 66], [59,, 61, 65], [70, 74, 78, 86], [79,, 81, 85]]);
      }));

      function importItems(_x69) {
        return _ref46.apply(this, arguments);
      }

      return importItems;
    }()
  }, {
    key: "getAllItemsJSONData",
    value: function () {
      var _ref47 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee38(keys, authParams, returnNullIfEmpty) {
        return regeneratorRuntime.wrap(function _callee38$(_context38) {
          while (1) {
            switch (_context38.prev = _context38.next) {
              case 0:
                return _context38.abrupt("return", this.getJSONDataForItems(this.allItems, keys, authParams, returnNullIfEmpty));

              case 1:
              case "end":
                return _context38.stop();
            }
          }
        }, _callee38, this);
      }));

      function getAllItemsJSONData(_x70, _x71, _x72) {
        return _ref47.apply(this, arguments);
      }

      return getAllItemsJSONData;
    }()
  }, {
    key: "getJSONDataForItems",
    value: function () {
      var _ref48 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee39(items, keys, authParams, returnNullIfEmpty) {
        return regeneratorRuntime.wrap(function _callee39$(_context39) {
          while (1) {
            switch (_context39.prev = _context39.next) {
              case 0:
                return _context39.abrupt("return", Promise.all(items.map(function (item) {
                  var itemParams = new SFItemParams(item, keys, authParams);
                  return itemParams.paramsForExportFile();
                })).then(function (items) {
                  if (returnNullIfEmpty && items.length == 0) {
                    return null;
                  }

                  var data = { items: items };

                  if (keys) {
                    // auth params are only needed when encrypted with a standard file key
                    data["auth_params"] = authParams;
                  }

                  return JSON.stringify(data, null, 2 /* pretty print */);
                }));

              case 1:
              case "end":
                return _context39.stop();
            }
          }
        }, _callee39, this);
      }));

      function getJSONDataForItems(_x73, _x74, _x75, _x76) {
        return _ref48.apply(this, arguments);
      }

      return getJSONDataForItems;
    }()
  }, {
    key: "computeDataIntegrityHash",
    value: function () {
      var _ref49 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee40() {
        var items, dates, string, hash;
        return regeneratorRuntime.wrap(function _callee40$(_context40) {
          while (1) {
            switch (_context40.prev = _context40.next) {
              case 0:
                _context40.prev = 0;
                items = this.allNondummyItems.sort(function (a, b) {
                  return b.updated_at - a.updated_at;
                });
                dates = items.map(function (item) {
                  return item.updatedAtTimestamp();
                });
                string = dates.join(",");
                _context40.next = 6;
                return SFJS.crypto.sha256(string);

              case 6:
                hash = _context40.sent;
                return _context40.abrupt("return", hash);

              case 10:
                _context40.prev = 10;
                _context40.t0 = _context40["catch"](0);

                console.error("Error computing data integrity hash", _context40.t0);
                return _context40.abrupt("return", null);

              case 14:
              case "end":
                return _context40.stop();
            }
          }
        }, _callee40, this, [[0, 10]]);
      }));

      function computeDataIntegrityHash() {
        return _ref49.apply(this, arguments);
      }

      return computeDataIntegrityHash;
    }()
  }, {
    key: "allItems",
    get: function get() {
      return this.items.slice();
    }
  }, {
    key: "allNondummyItems",
    get: function get() {
      return this.items.filter(function (item) {
        return !item.dummy;
      });
    }
  }]);

  return SFModelManager;
}();

;
var SFPrivilegesManager = exports.SFPrivilegesManager = function () {
  function SFPrivilegesManager(modelManager, syncManager, singletonManager) {
    _classCallCheck(this, SFPrivilegesManager);

    this.modelManager = modelManager;
    this.syncManager = syncManager;
    this.singletonManager = singletonManager;

    this.loadPrivileges();

    SFPrivilegesManager.CredentialAccountPassword = "CredentialAccountPassword";
    SFPrivilegesManager.CredentialLocalPasscode = "CredentialLocalPasscode";

    SFPrivilegesManager.ActionManageExtensions = "ActionManageExtensions";
    SFPrivilegesManager.ActionManageBackups = "ActionManageBackups";
    SFPrivilegesManager.ActionViewProtectedNotes = "ActionViewProtectedNotes";
    SFPrivilegesManager.ActionManagePrivileges = "ActionManagePrivileges";
    SFPrivilegesManager.ActionManagePasscode = "ActionManagePasscode";
    SFPrivilegesManager.ActionDeleteNote = "ActionDeleteNote";

    SFPrivilegesManager.SessionExpiresAtKey = "SessionExpiresAtKey";
    SFPrivilegesManager.SessionLengthKey = "SessionLengthKey";

    SFPrivilegesManager.SessionLengthNone = 0;
    SFPrivilegesManager.SessionLengthFiveMinutes = 300;
    SFPrivilegesManager.SessionLengthOneHour = 3600;
    SFPrivilegesManager.SessionLengthOneWeek = 604800;

    this.availableActions = [SFPrivilegesManager.ActionViewProtectedNotes, SFPrivilegesManager.ActionDeleteNote, SFPrivilegesManager.ActionManagePasscode, SFPrivilegesManager.ActionManageBackups, SFPrivilegesManager.ActionManageExtensions, SFPrivilegesManager.ActionManagePrivileges];

    this.availableCredentials = [SFPrivilegesManager.CredentialAccountPassword, SFPrivilegesManager.CredentialLocalPasscode];

    this.sessionLengths = [SFPrivilegesManager.SessionLengthNone, SFPrivilegesManager.SessionLengthFiveMinutes, SFPrivilegesManager.SessionLengthOneHour, SFPrivilegesManager.SessionLengthOneWeek, SFPrivilegesManager.SessionLengthIndefinite];
  }

  /*
  async delegate.isOffline()
  async delegate.hasLocalPasscode()
  async delegate.saveToStorage(key, value)
  async delegate.getFromStorage(key)
  async delegate.verifyAccountPassword
  async delegate.verifyLocalPasscode
  */


  _createClass(SFPrivilegesManager, [{
    key: "setDelegate",
    value: function setDelegate(delegate) {
      this.delegate = delegate;
    }
  }, {
    key: "getAvailableActions",
    value: function getAvailableActions() {
      return this.availableActions;
    }
  }, {
    key: "getAvailableCredentials",
    value: function getAvailableCredentials() {
      return this.availableCredentials;
    }
  }, {
    key: "netCredentialsForAction",
    value: function () {
      var _ref50 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee41(action) {
        var credentials, netCredentials, _iteratorNormalCompletion31, _didIteratorError31, _iteratorError31, _iterator31, _step31, cred, isOffline, hasLocalPasscode;

        return regeneratorRuntime.wrap(function _callee41$(_context41) {
          while (1) {
            switch (_context41.prev = _context41.next) {
              case 0:
                _context41.next = 2;
                return this.getPrivileges();

              case 2:
                _context41.t0 = action;
                credentials = _context41.sent.getCredentialsForAction(_context41.t0);
                netCredentials = [];
                _iteratorNormalCompletion31 = true;
                _didIteratorError31 = false;
                _iteratorError31 = undefined;
                _context41.prev = 8;
                _iterator31 = credentials[Symbol.iterator]();

              case 10:
                if (_iteratorNormalCompletion31 = (_step31 = _iterator31.next()).done) {
                  _context41.next = 27;
                  break;
                }

                cred = _step31.value;

                if (!(cred == SFPrivilegesManager.CredentialAccountPassword)) {
                  _context41.next = 19;
                  break;
                }

                _context41.next = 15;
                return this.delegate.isOffline();

              case 15:
                isOffline = _context41.sent;

                if (!isOffline) {
                  netCredentials.push(cred);
                }
                _context41.next = 24;
                break;

              case 19:
                if (!(cred == SFPrivilegesManager.CredentialLocalPasscode)) {
                  _context41.next = 24;
                  break;
                }

                _context41.next = 22;
                return this.delegate.hasLocalPasscode();

              case 22:
                hasLocalPasscode = _context41.sent;

                if (hasLocalPasscode) {
                  netCredentials.push(cred);
                }

              case 24:
                _iteratorNormalCompletion31 = true;
                _context41.next = 10;
                break;

              case 27:
                _context41.next = 33;
                break;

              case 29:
                _context41.prev = 29;
                _context41.t1 = _context41["catch"](8);
                _didIteratorError31 = true;
                _iteratorError31 = _context41.t1;

              case 33:
                _context41.prev = 33;
                _context41.prev = 34;

                if (!_iteratorNormalCompletion31 && _iterator31.return) {
                  _iterator31.return();
                }

              case 36:
                _context41.prev = 36;

                if (!_didIteratorError31) {
                  _context41.next = 39;
                  break;
                }

                throw _iteratorError31;

              case 39:
                return _context41.finish(36);

              case 40:
                return _context41.finish(33);

              case 41:
                return _context41.abrupt("return", netCredentials);

              case 42:
              case "end":
                return _context41.stop();
            }
          }
        }, _callee41, this, [[8, 29, 33, 41], [34,, 36, 40]]);
      }));

      function netCredentialsForAction(_x77) {
        return _ref50.apply(this, arguments);
      }

      return netCredentialsForAction;
    }()
  }, {
    key: "loadPrivileges",
    value: function () {
      var _ref51 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee43() {
        var _this11 = this;

        return regeneratorRuntime.wrap(function _callee43$(_context43) {
          while (1) {
            switch (_context43.prev = _context43.next) {
              case 0:
                if (!this.loadPromise) {
                  _context43.next = 2;
                  break;
                }

                return _context43.abrupt("return", this.loadPromise);

              case 2:

                this.loadPromise = new Promise(function (resolve, reject) {
                  var privsContentType = SFPrivileges.contentType();
                  var contentTypePredicate = new SFPredicate("content_type", "=", privsContentType);
                  _this11.singletonManager.registerSingleton([contentTypePredicate], function (resolvedSingleton) {
                    _this11.privileges = resolvedSingleton;
                    resolve(resolvedSingleton);
                  }, function () {
                    var _ref52 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee42(valueCallback) {
                      var privs;
                      return regeneratorRuntime.wrap(function _callee42$(_context42) {
                        while (1) {
                          switch (_context42.prev = _context42.next) {
                            case 0:
                              // Safe to create. Create and return object.
                              privs = new SFPrivileges({ content_type: privsContentType });

                              if (SFJS.crypto.generateUUIDSync) {
                                _context42.next = 4;
                                break;
                              }

                              _context42.next = 4;
                              return privs.initUUID();

                            case 4:
                              _this11.modelManager.addItem(privs);
                              _this11.modelManager.setItemDirty(privs, true);
                              _this11.syncManager.sync();
                              valueCallback(privs);
                              resolve(privs);

                            case 9:
                            case "end":
                              return _context42.stop();
                          }
                        }
                      }, _callee42, _this11);
                    }));

                    return function (_x78) {
                      return _ref52.apply(this, arguments);
                    };
                  }());
                });

                return _context43.abrupt("return", this.loadPromise);

              case 4:
              case "end":
                return _context43.stop();
            }
          }
        }, _callee43, this);
      }));

      function loadPrivileges() {
        return _ref51.apply(this, arguments);
      }

      return loadPrivileges;
    }()
  }, {
    key: "getPrivileges",
    value: function () {
      var _ref53 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee44() {
        return regeneratorRuntime.wrap(function _callee44$(_context44) {
          while (1) {
            switch (_context44.prev = _context44.next) {
              case 0:
                if (!this.privileges) {
                  _context44.next = 4;
                  break;
                }

                return _context44.abrupt("return", this.privileges);

              case 4:
                return _context44.abrupt("return", this.loadPrivileges());

              case 5:
              case "end":
                return _context44.stop();
            }
          }
        }, _callee44, this);
      }));

      function getPrivileges() {
        return _ref53.apply(this, arguments);
      }

      return getPrivileges;
    }()
  }, {
    key: "displayInfoForCredential",
    value: function displayInfoForCredential(credential) {
      var metadata = {};

      metadata[SFPrivilegesManager.CredentialAccountPassword] = {
        label: "Account Password",
        prompt: "Please enter your account password."
      };

      metadata[SFPrivilegesManager.CredentialLocalPasscode] = {
        label: "Local Passcode",
        prompt: "Please enter your local passcode."
      };

      return metadata[credential];
    }
  }, {
    key: "displayInfoForAction",
    value: function displayInfoForAction(action) {
      var metadata = {};

      metadata[SFPrivilegesManager.ActionManageExtensions] = {
        label: "Manage Extensions"
      };

      metadata[SFPrivilegesManager.ActionManageBackups] = {
        label: "Download/Import Backups"
      };

      metadata[SFPrivilegesManager.ActionViewProtectedNotes] = {
        label: "View Protected Notes"
      };

      metadata[SFPrivilegesManager.ActionManagePrivileges] = {
        label: "Manage Privileges"
      };

      metadata[SFPrivilegesManager.ActionManagePasscode] = {
        label: "Manage Passcode"
      };

      metadata[SFPrivilegesManager.ActionDeleteNote] = {
        label: "Delete Notes"
      };

      return metadata[action];
    }
  }, {
    key: "getSessionLengthOptions",
    value: function getSessionLengthOptions() {
      return [{
        value: SFPrivilegesManager.SessionLengthNone,
        label: "Don't Remember"
      }, {
        value: SFPrivilegesManager.SessionLengthFiveMinutes,
        label: "5 Minutes"
      }, {
        value: SFPrivilegesManager.SessionLengthOneHour,
        label: "1 Hour"
      }, {
        value: SFPrivilegesManager.SessionLengthOneWeek,
        label: "1 Week"
      }];
    }
  }, {
    key: "setSessionLength",
    value: function () {
      var _ref54 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee45(length) {
        var addToNow, expiresAt;
        return regeneratorRuntime.wrap(function _callee45$(_context45) {
          while (1) {
            switch (_context45.prev = _context45.next) {
              case 0:
                addToNow = function addToNow(seconds) {
                  var date = new Date();
                  date.setSeconds(date.getSeconds() + seconds);
                  return date;
                };

                expiresAt = addToNow(length);
                return _context45.abrupt("return", Promise.all([this.delegate.saveToStorage(SFPrivilegesManager.SessionExpiresAtKey, JSON.stringify(expiresAt)), this.delegate.saveToStorage(SFPrivilegesManager.SessionLengthKey, JSON.stringify(length))]));

              case 3:
              case "end":
                return _context45.stop();
            }
          }
        }, _callee45, this);
      }));

      function setSessionLength(_x79) {
        return _ref54.apply(this, arguments);
      }

      return setSessionLength;
    }()
  }, {
    key: "clearSession",
    value: function () {
      var _ref55 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee46() {
        return regeneratorRuntime.wrap(function _callee46$(_context46) {
          while (1) {
            switch (_context46.prev = _context46.next) {
              case 0:
                return _context46.abrupt("return", this.setSessionLength(SFPrivilegesManager.SessionLengthNone));

              case 1:
              case "end":
                return _context46.stop();
            }
          }
        }, _callee46, this);
      }));

      function clearSession() {
        return _ref55.apply(this, arguments);
      }

      return clearSession;
    }()
  }, {
    key: "getSelectedSessionLength",
    value: function () {
      var _ref56 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee47() {
        var length;
        return regeneratorRuntime.wrap(function _callee47$(_context47) {
          while (1) {
            switch (_context47.prev = _context47.next) {
              case 0:
                _context47.next = 2;
                return this.delegate.getFromStorage(SFPrivilegesManager.SessionLengthKey);

              case 2:
                length = _context47.sent;

                if (!length) {
                  _context47.next = 7;
                  break;
                }

                return _context47.abrupt("return", JSON.parse(length));

              case 7:
                return _context47.abrupt("return", SFPrivilegesManager.SessionLengthNone);

              case 8:
              case "end":
                return _context47.stop();
            }
          }
        }, _callee47, this);
      }));

      function getSelectedSessionLength() {
        return _ref56.apply(this, arguments);
      }

      return getSelectedSessionLength;
    }()
  }, {
    key: "getSessionExpirey",
    value: function () {
      var _ref57 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee48() {
        var expiresAt;
        return regeneratorRuntime.wrap(function _callee48$(_context48) {
          while (1) {
            switch (_context48.prev = _context48.next) {
              case 0:
                _context48.next = 2;
                return this.delegate.getFromStorage(SFPrivilegesManager.SessionExpiresAtKey);

              case 2:
                expiresAt = _context48.sent;

                if (!expiresAt) {
                  _context48.next = 7;
                  break;
                }

                return _context48.abrupt("return", new Date(JSON.parse(expiresAt)));

              case 7:
                return _context48.abrupt("return", new Date());

              case 8:
              case "end":
                return _context48.stop();
            }
          }
        }, _callee48, this);
      }));

      function getSessionExpirey() {
        return _ref57.apply(this, arguments);
      }

      return getSessionExpirey;
    }()
  }, {
    key: "actionHasPrivilegesConfigured",
    value: function () {
      var _ref58 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee49(action) {
        return regeneratorRuntime.wrap(function _callee49$(_context49) {
          while (1) {
            switch (_context49.prev = _context49.next) {
              case 0:
                _context49.next = 2;
                return this.netCredentialsForAction(action);

              case 2:
                _context49.t0 = _context49.sent.length;
                return _context49.abrupt("return", _context49.t0 > 0);

              case 4:
              case "end":
                return _context49.stop();
            }
          }
        }, _callee49, this);
      }));

      function actionHasPrivilegesConfigured(_x80) {
        return _ref58.apply(this, arguments);
      }

      return actionHasPrivilegesConfigured;
    }()
  }, {
    key: "actionRequiresPrivilege",
    value: function () {
      var _ref59 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee50(action) {
        var expiresAt, netCredentials;
        return regeneratorRuntime.wrap(function _callee50$(_context50) {
          while (1) {
            switch (_context50.prev = _context50.next) {
              case 0:
                _context50.next = 2;
                return this.getSessionExpirey();

              case 2:
                expiresAt = _context50.sent;

                if (!(expiresAt > new Date())) {
                  _context50.next = 5;
                  break;
                }

                return _context50.abrupt("return", false);

              case 5:
                _context50.next = 7;
                return this.netCredentialsForAction(action);

              case 7:
                netCredentials = _context50.sent;
                return _context50.abrupt("return", netCredentials.length > 0);

              case 9:
              case "end":
                return _context50.stop();
            }
          }
        }, _callee50, this);
      }));

      function actionRequiresPrivilege(_x81) {
        return _ref59.apply(this, arguments);
      }

      return actionRequiresPrivilege;
    }()
  }, {
    key: "savePrivileges",
    value: function () {
      var _ref60 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee51() {
        var privs;
        return regeneratorRuntime.wrap(function _callee51$(_context51) {
          while (1) {
            switch (_context51.prev = _context51.next) {
              case 0:
                _context51.next = 2;
                return this.getPrivileges();

              case 2:
                privs = _context51.sent;

                this.modelManager.setItemDirty(privs, true);
                this.syncManager.sync();

              case 5:
              case "end":
                return _context51.stop();
            }
          }
        }, _callee51, this);
      }));

      function savePrivileges() {
        return _ref60.apply(this, arguments);
      }

      return savePrivileges;
    }()
  }, {
    key: "authenticateAction",
    value: function () {
      var _ref61 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee52(action, credentialAuthMapping) {
        var requiredCredentials, successfulCredentials, failedCredentials, _iteratorNormalCompletion32, _didIteratorError32, _iteratorError32, _iterator32, _step32, requiredCredential, passesAuth;

        return regeneratorRuntime.wrap(function _callee52$(_context52) {
          while (1) {
            switch (_context52.prev = _context52.next) {
              case 0:
                _context52.next = 2;
                return this.netCredentialsForAction(action);

              case 2:
                requiredCredentials = _context52.sent;
                successfulCredentials = [], failedCredentials = [];
                _iteratorNormalCompletion32 = true;
                _didIteratorError32 = false;
                _iteratorError32 = undefined;
                _context52.prev = 7;
                _iterator32 = requiredCredentials[Symbol.iterator]();

              case 9:
                if (_iteratorNormalCompletion32 = (_step32 = _iterator32.next()).done) {
                  _context52.next = 18;
                  break;
                }

                requiredCredential = _step32.value;
                _context52.next = 13;
                return this._verifyAuthenticationParameters(requiredCredential, credentialAuthMapping[requiredCredential]);

              case 13:
                passesAuth = _context52.sent;

                if (passesAuth) {
                  successfulCredentials.push(requiredCredential);
                } else {
                  failedCredentials.push(requiredCredential);
                }

              case 15:
                _iteratorNormalCompletion32 = true;
                _context52.next = 9;
                break;

              case 18:
                _context52.next = 24;
                break;

              case 20:
                _context52.prev = 20;
                _context52.t0 = _context52["catch"](7);
                _didIteratorError32 = true;
                _iteratorError32 = _context52.t0;

              case 24:
                _context52.prev = 24;
                _context52.prev = 25;

                if (!_iteratorNormalCompletion32 && _iterator32.return) {
                  _iterator32.return();
                }

              case 27:
                _context52.prev = 27;

                if (!_didIteratorError32) {
                  _context52.next = 30;
                  break;
                }

                throw _iteratorError32;

              case 30:
                return _context52.finish(27);

              case 31:
                return _context52.finish(24);

              case 32:
                return _context52.abrupt("return", {
                  success: failedCredentials.length == 0,
                  successfulCredentials: successfulCredentials,
                  failedCredentials: failedCredentials
                });

              case 33:
              case "end":
                return _context52.stop();
            }
          }
        }, _callee52, this, [[7, 20, 24, 32], [25,, 27, 31]]);
      }));

      function authenticateAction(_x82, _x83) {
        return _ref61.apply(this, arguments);
      }

      return authenticateAction;
    }()
  }, {
    key: "_verifyAuthenticationParameters",
    value: function () {
      var _ref62 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee55(credential, value) {
        var _this12 = this;

        var verifyAccountPassword, verifyLocalPasscode;
        return regeneratorRuntime.wrap(function _callee55$(_context55) {
          while (1) {
            switch (_context55.prev = _context55.next) {
              case 0:
                verifyAccountPassword = function () {
                  var _ref63 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee53(password) {
                    return regeneratorRuntime.wrap(function _callee53$(_context53) {
                      while (1) {
                        switch (_context53.prev = _context53.next) {
                          case 0:
                            return _context53.abrupt("return", _this12.delegate.verifyAccountPassword(password));

                          case 1:
                          case "end":
                            return _context53.stop();
                        }
                      }
                    }, _callee53, _this12);
                  }));

                  return function verifyAccountPassword(_x86) {
                    return _ref63.apply(this, arguments);
                  };
                }();

                verifyLocalPasscode = function () {
                  var _ref64 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee54(passcode) {
                    return regeneratorRuntime.wrap(function _callee54$(_context54) {
                      while (1) {
                        switch (_context54.prev = _context54.next) {
                          case 0:
                            return _context54.abrupt("return", _this12.delegate.verifyLocalPasscode(passcode));

                          case 1:
                          case "end":
                            return _context54.stop();
                        }
                      }
                    }, _callee54, _this12);
                  }));

                  return function verifyLocalPasscode(_x87) {
                    return _ref64.apply(this, arguments);
                  };
                }();

                if (!(credential == SFPrivilegesManager.CredentialAccountPassword)) {
                  _context55.next = 6;
                  break;
                }

                return _context55.abrupt("return", verifyAccountPassword(value));

              case 6:
                if (!(credential == SFPrivilegesManager.CredentialLocalPasscode)) {
                  _context55.next = 8;
                  break;
                }

                return _context55.abrupt("return", verifyLocalPasscode(value));

              case 8:
              case "end":
                return _context55.stop();
            }
          }
        }, _callee55, this);
      }));

      function _verifyAuthenticationParameters(_x84, _x85) {
        return _ref62.apply(this, arguments);
      }

      return _verifyAuthenticationParameters;
    }()
  }]);

  return SFPrivilegesManager;
}();

;var SessionHistoryPersistKey = "sessionHistory_persist";
var SessionHistoryRevisionsKey = "sessionHistory_revisions";
var SessionHistoryAutoOptimizeKey = "sessionHistory_autoOptimize";

var SFSessionHistoryManager = exports.SFSessionHistoryManager = function () {
  function SFSessionHistoryManager(modelManager, storageManager, keyRequestHandler, contentTypes, timeout) {
    var _this13 = this;

    _classCallCheck(this, SFSessionHistoryManager);

    this.modelManager = modelManager;
    this.storageManager = storageManager;
    this.$timeout = timeout || setTimeout.bind(window);

    // Required to persist the encrypted form of SFHistorySession
    this.keyRequestHandler = keyRequestHandler;

    this.loadFromDisk().then(function () {
      _this13.modelManager.addItemSyncObserver("session-history", contentTypes, function (allItems, validItems, deletedItems, source, sourceKey) {
        var _iteratorNormalCompletion33 = true;
        var _didIteratorError33 = false;
        var _iteratorError33 = undefined;

        try {
          for (var _iterator33 = allItems[Symbol.iterator](), _step33; !(_iteratorNormalCompletion33 = (_step33 = _iterator33.next()).done); _iteratorNormalCompletion33 = true) {
            var item = _step33.value;

            try {
              _this13.addHistoryEntryForItem(item);
            } catch (e) {
              console.log("Caught exception while trying to add item history entry", e);
            }
          }
        } catch (err) {
          _didIteratorError33 = true;
          _iteratorError33 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion33 && _iterator33.return) {
              _iterator33.return();
            }
          } finally {
            if (_didIteratorError33) {
              throw _iteratorError33;
            }
          }
        }
      });
    });
  }

  _createClass(SFSessionHistoryManager, [{
    key: "encryptionParams",
    value: function () {
      var _ref65 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee56() {
        return regeneratorRuntime.wrap(function _callee56$(_context56) {
          while (1) {
            switch (_context56.prev = _context56.next) {
              case 0:
                return _context56.abrupt("return", this.keyRequestHandler());

              case 1:
              case "end":
                return _context56.stop();
            }
          }
        }, _callee56, this);
      }));

      function encryptionParams() {
        return _ref65.apply(this, arguments);
      }

      return encryptionParams;
    }()
  }, {
    key: "addHistoryEntryForItem",
    value: function addHistoryEntryForItem(item) {
      var _this14 = this;

      var persistableItemParams = {
        uuid: item.uuid,
        content_type: item.content_type,
        updated_at: item.updated_at,
        content: item.content
      };

      var entry = this.historySession.addEntryForItem(persistableItemParams);

      if (this.autoOptimize) {
        this.historySession.optimizeHistoryForItem(item);
      }

      if (entry && this.diskEnabled) {
        // Debounce, clear existing timeout
        if (this.diskTimeout) {
          if (this.$timeout.hasOwnProperty("cancel")) {
            this.$timeout.cancel(this.diskTimeout);
          } else {
            clearTimeout(this.diskTimeout);
          }
        };
        this.diskTimeout = this.$timeout(function () {
          _this14.saveToDisk();
        }, 2000);
      }
    }
  }, {
    key: "historyForItem",
    value: function historyForItem(item) {
      return this.historySession.historyForItem(item);
    }
  }, {
    key: "clearHistoryForItem",
    value: function () {
      var _ref66 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee57(item) {
        return regeneratorRuntime.wrap(function _callee57$(_context57) {
          while (1) {
            switch (_context57.prev = _context57.next) {
              case 0:
                this.historySession.clearItemHistory(item);
                return _context57.abrupt("return", this.saveToDisk());

              case 2:
              case "end":
                return _context57.stop();
            }
          }
        }, _callee57, this);
      }));

      function clearHistoryForItem(_x88) {
        return _ref66.apply(this, arguments);
      }

      return clearHistoryForItem;
    }()
  }, {
    key: "clearAllHistory",
    value: function () {
      var _ref67 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee58() {
        return regeneratorRuntime.wrap(function _callee58$(_context58) {
          while (1) {
            switch (_context58.prev = _context58.next) {
              case 0:
                this.historySession.clearAllHistory();
                return _context58.abrupt("return", this.storageManager.removeItem(SessionHistoryRevisionsKey));

              case 2:
              case "end":
                return _context58.stop();
            }
          }
        }, _callee58, this);
      }));

      function clearAllHistory() {
        return _ref67.apply(this, arguments);
      }

      return clearAllHistory;
    }()
  }, {
    key: "toggleDiskSaving",
    value: function () {
      var _ref68 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee59() {
        return regeneratorRuntime.wrap(function _callee59$(_context59) {
          while (1) {
            switch (_context59.prev = _context59.next) {
              case 0:
                this.diskEnabled = !this.diskEnabled;

                if (!this.diskEnabled) {
                  _context59.next = 6;
                  break;
                }

                this.storageManager.setItem(SessionHistoryPersistKey, JSON.stringify(true));
                this.saveToDisk();
                _context59.next = 8;
                break;

              case 6:
                this.storageManager.setItem(SessionHistoryPersistKey, JSON.stringify(false));
                return _context59.abrupt("return", this.storageManager.removeItem(SessionHistoryRevisionsKey));

              case 8:
              case "end":
                return _context59.stop();
            }
          }
        }, _callee59, this);
      }));

      function toggleDiskSaving() {
        return _ref68.apply(this, arguments);
      }

      return toggleDiskSaving;
    }()
  }, {
    key: "saveToDisk",
    value: function () {
      var _ref69 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee60() {
        var _this15 = this;

        var encryptionParams, itemParams;
        return regeneratorRuntime.wrap(function _callee60$(_context60) {
          while (1) {
            switch (_context60.prev = _context60.next) {
              case 0:
                if (this.diskEnabled) {
                  _context60.next = 2;
                  break;
                }

                return _context60.abrupt("return");

              case 2:
                _context60.next = 4;
                return this.encryptionParams();

              case 4:
                encryptionParams = _context60.sent;
                itemParams = new SFItemParams(this.historySession, encryptionParams.keys, encryptionParams.auth_params);

                itemParams.paramsForSync().then(function (syncParams) {
                  // console.log("Saving to disk", syncParams);
                  _this15.storageManager.setItem(SessionHistoryRevisionsKey, JSON.stringify(syncParams));
                });

              case 7:
              case "end":
                return _context60.stop();
            }
          }
        }, _callee60, this);
      }));

      function saveToDisk() {
        return _ref69.apply(this, arguments);
      }

      return saveToDisk;
    }()
  }, {
    key: "loadFromDisk",
    value: function () {
      var _ref70 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee61() {
        var diskValue, historyValue, encryptionParams, historySession, autoOptimizeValue;
        return regeneratorRuntime.wrap(function _callee61$(_context61) {
          while (1) {
            switch (_context61.prev = _context61.next) {
              case 0:
                _context61.next = 2;
                return this.storageManager.getItem(SessionHistoryPersistKey);

              case 2:
                diskValue = _context61.sent;

                if (diskValue) {
                  this.diskEnabled = JSON.parse(diskValue);
                }

                _context61.next = 6;
                return this.storageManager.getItem(SessionHistoryRevisionsKey);

              case 6:
                historyValue = _context61.sent;

                if (!historyValue) {
                  _context61.next = 18;
                  break;
                }

                historyValue = JSON.parse(historyValue);
                _context61.next = 11;
                return this.encryptionParams();

              case 11:
                encryptionParams = _context61.sent;
                _context61.next = 14;
                return SFJS.itemTransformer.decryptItem(historyValue, encryptionParams.keys);

              case 14:
                historySession = new SFHistorySession(historyValue);

                this.historySession = historySession;
                _context61.next = 19;
                break;

              case 18:
                this.historySession = new SFHistorySession();

              case 19:
                _context61.next = 21;
                return this.storageManager.getItem(SessionHistoryAutoOptimizeKey);

              case 21:
                autoOptimizeValue = _context61.sent;

                if (autoOptimizeValue) {
                  this.autoOptimize = JSON.parse(autoOptimizeValue);
                } else {
                  // default value is true
                  this.autoOptimize = true;
                }

              case 23:
              case "end":
                return _context61.stop();
            }
          }
        }, _callee61, this);
      }));

      function loadFromDisk() {
        return _ref70.apply(this, arguments);
      }

      return loadFromDisk;
    }()
  }, {
    key: "toggleAutoOptimize",
    value: function () {
      var _ref71 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee62() {
        return regeneratorRuntime.wrap(function _callee62$(_context62) {
          while (1) {
            switch (_context62.prev = _context62.next) {
              case 0:
                this.autoOptimize = !this.autoOptimize;

                if (this.autoOptimize) {
                  this.storageManager.setItem(SessionHistoryAutoOptimizeKey, JSON.stringify(true));
                } else {
                  this.storageManager.setItem(SessionHistoryAutoOptimizeKey, JSON.stringify(false));
                }

              case 2:
              case "end":
                return _context62.stop();
            }
          }
        }, _callee62, this);
      }));

      function toggleAutoOptimize() {
        return _ref71.apply(this, arguments);
      }

      return toggleAutoOptimize;
    }()
  }]);

  return SFSessionHistoryManager;
}();

; /*
   The SingletonManager allows controllers to register an item as a singleton, which means only one instance of that model
   should exist, both on the server and on the client. When the SingletonManager detects multiple items matching the singleton predicate,
   the oldest ones will be deleted, leaving the newest ones. (See 4/28/18 update. We now choose the earliest created one as the winner.).
    (This no longer fully applies, See 4/28/18 update.) We will treat the model most recently arrived from the server as the most recent one. The reason for this is,
   if you're offline, a singleton can be created, as in the case of UserPreferneces. Then when you sign in, you'll retrieve your actual user preferences.
   In that case, even though the offline singleton has a more recent updated_at, the server retreived value is the one we care more about.
    4/28/18: I'm seeing this issue: if you have the app open in one window, then in another window sign in, and during sign in,
   click Refresh (or autorefresh occurs) in the original signed in window, then you will happen to receive from the server the newly created
   Extensions singleton, and it will be mistaken (it just looks like a regular retrieved item, since nothing is in saved) for a fresh, latest copy, and replace the current instance.
   This has happened to me and many users.
   A puzzling issue, but what if instead of resolving singletons by choosing the one most recently modified, we choose the one with the earliest create date?
   This way, we don't care when it was modified, but we always, always choose the item that was created first. This way, we always deal with the same item.
  */

var SFSingletonManager = exports.SFSingletonManager = function () {
  function SFSingletonManager(modelManager, syncManager) {
    var _this16 = this;

    _classCallCheck(this, SFSingletonManager);

    this.syncManager = syncManager;
    this.modelManager = modelManager;
    this.singletonHandlers = [];

    // We use sync observer instead of syncEvent `local-data-incremental-load`, because we want singletons
    // to resolve with the first priority, because they generally dictate app state.
    // If we used local-data-incremental-load, and 1 item was important singleton and 99 were heavy components,
    // then given the random nature of notifiying observers, the heavy components would spend a lot of time loading first,
    // here, we priortize ours loading as most important
    modelManager.addItemSyncObserverWithPriority({
      id: "sf-singleton-manager",
      types: "*",
      priority: -1,
      callback: function callback(allItems, validItems, deletedItems, source, sourceKey) {
        // Inside resolveSingletons, we are going to set items as dirty. If we don't stop here it will be infinite recursion.
        if (source === SFModelManager.MappingSourceLocalDirtied) {
          return;
        }
        _this16.resolveSingletons(modelManager.allNondummyItems, null, true);
      }
    });

    syncManager.addEventHandler(function (syncEvent, data) {
      if (syncEvent == "local-data-loaded") {
        _this16.resolveSingletons(modelManager.allNondummyItems, null, true);
        _this16.initialDataLoaded = true;
      } else if (syncEvent == "sync:completed") {
        // Wait for initial data load before handling any sync. If we don't want for initial data load,
        // then the singleton resolver won't have the proper items to work with to determine whether to resolve or create.
        if (!_this16.initialDataLoaded) {
          return;
        }
        // The reason we also need to consider savedItems in consolidating singletons is in case of sync conflicts,
        // a new item can be created, but is never processed through "retrievedItems" since it is only created locally then saved.

        // HOWEVER, by considering savedItems, we are now ruining everything, especially during sign in. A singleton can be created
        // offline, and upon sign in, will sync all items to the server, and by combining retrievedItems & savedItems, and only choosing
        // the latest, you are now resolving to the most recent one, which is in the savedItems list and not retrieved items, defeating
        // the whole purpose of this thing.

        // Updated solution: resolveSingletons will now evaluate both of these arrays separately.
        _this16.resolveSingletons(data.retrievedItems, data.savedItems);
      }
    });

    /*
      If an item alternates its uuid on registration, singletonHandlers might need to update
      their local reference to the object, since the object reference will change on uuid alternation
    */
    modelManager.addModelUuidChangeObserver("singleton-manager", function (oldModel, newModel) {
      var _iteratorNormalCompletion34 = true;
      var _didIteratorError34 = false;
      var _iteratorError34 = undefined;

      try {
        for (var _iterator34 = _this16.singletonHandlers[Symbol.iterator](), _step34; !(_iteratorNormalCompletion34 = (_step34 = _iterator34.next()).done); _iteratorNormalCompletion34 = true) {
          var handler = _step34.value;

          if (handler.singleton && SFPredicate.ItemSatisfiesPredicates(newModel, handler.predicates)) {
            // Reference is now invalid, calling resolveSingleton should update it
            handler.singleton = null;
            _this16.resolveSingletons([newModel]);
          }
        }
      } catch (err) {
        _didIteratorError34 = true;
        _iteratorError34 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion34 && _iterator34.return) {
            _iterator34.return();
          }
        } finally {
          if (_didIteratorError34) {
            throw _iteratorError34;
          }
        }
      }
    });
  }

  _createClass(SFSingletonManager, [{
    key: "registerSingleton",
    value: function registerSingleton(predicates, resolveCallback, createBlock) {
      /*
      predicate: a key/value pair that specifies properties that should match in order for an item to be considered a predicate
      resolveCallback: called when one or more items are deleted and a new item becomes the reigning singleton
      createBlock: called when a sync is complete and no items are found. The createBlock should create the item and return it.
      */
      this.singletonHandlers.push({
        predicates: predicates,
        resolutionCallback: resolveCallback,
        createBlock: createBlock
      });
    }
  }, {
    key: "resolveSingletons",
    value: function resolveSingletons(retrievedItems, savedItems, initialLoad) {
      var _this17 = this;

      retrievedItems = retrievedItems || [];
      savedItems = savedItems || [];

      var _loop3 = function _loop3(singletonHandler) {
        var predicates = singletonHandler.predicates.slice();
        var retrievedSingletonItems = _this17.modelManager.filterItemsWithPredicates(retrievedItems, predicates);

        var handleCreation = function handleCreation() {
          if (singletonHandler.createBlock) {
            singletonHandler.pendingCreateBlockCallback = true;
            singletonHandler.createBlock(function (created) {
              singletonHandler.singleton = created;
              singletonHandler.pendingCreateBlockCallback = false;
              singletonHandler.resolutionCallback && singletonHandler.resolutionCallback(created);
            });
          }
        };

        // We only want to consider saved items count to see if it's more than 0, and do nothing else with it.
        // This way we know there was some action and things need to be resolved. The saved items will come up
        // in filterItemsWithPredicate(this.modelManager.allNondummyItems) and be deleted anyway
        var savedSingletonItemsCount = _this17.modelManager.filterItemsWithPredicates(savedItems, predicates).length;

        if (retrievedSingletonItems.length > 0 || savedSingletonItemsCount > 0) {
          /*
            Check local inventory and make sure only 1 similar item exists. If more than 1, delete newest
            Note that this local inventory will also contain whatever is in retrievedItems.
          */
          var allExtantItemsMatchingPredicate = _this17.modelManager.itemsMatchingPredicates(predicates);

          /*
            Delete all but the earliest created
          */
          if (allExtantItemsMatchingPredicate.length >= 2) {
            var sorted = allExtantItemsMatchingPredicate.sort(function (a, b) {
              /*
                If compareFunction(a, b) is less than 0, sort a to an index lower than b, i.e. a comes first.
                If compareFunction(a, b) is greater than 0, sort b to an index lower than a, i.e. b comes first.
              */

              if (a.errorDecrypting) {
                return 1;
              }

              if (b.errorDecrypting) {
                return -1;
              }

              return a.created_at < b.created_at ? -1 : 1;
            });

            // The item that will be chosen to be kept
            var winningItem = sorted[0];

            // Items that will be deleted
            // Delete everything but the first one
            var toDelete = sorted.slice(1, sorted.length);

            var _iteratorNormalCompletion36 = true;
            var _didIteratorError36 = false;
            var _iteratorError36 = undefined;

            try {
              for (var _iterator36 = toDelete[Symbol.iterator](), _step36; !(_iteratorNormalCompletion36 = (_step36 = _iterator36.next()).done); _iteratorNormalCompletion36 = true) {
                var d = _step36.value;

                _this17.modelManager.setItemToBeDeleted(d);
              }
            } catch (err) {
              _didIteratorError36 = true;
              _iteratorError36 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion36 && _iterator36.return) {
                  _iterator36.return();
                }
              } finally {
                if (_didIteratorError36) {
                  throw _iteratorError36;
                }
              }
            }

            _this17.syncManager.sync();

            // Send remaining item to callback
            singletonHandler.singleton = winningItem;
            singletonHandler.resolutionCallback && singletonHandler.resolutionCallback(winningItem);
          } else if (allExtantItemsMatchingPredicate.length == 1) {
            var singleton = allExtantItemsMatchingPredicate[0];
            if (singleton.errorDecrypting) {
              // Delete the current singleton and create a new one
              _this17.modelManager.setItemToBeDeleted(singleton);
              handleCreation();
            } else if (!singletonHandler.singleton || singletonHandler.singleton !== singleton) {
              // Not yet notified interested parties of object
              singletonHandler.singleton = singleton;
              singletonHandler.resolutionCallback && singletonHandler.resolutionCallback(singleton);
            }
          }
        } else {
          // Retrieved items does not include any items of interest. If we don't have a singleton registered to this handler,
          // we need to create one. Only do this on actual sync completetions and not on initial data load. Because we want
          // to get the latest from the server before making the decision to create a new item
          if (!singletonHandler.singleton && !initialLoad && !singletonHandler.pendingCreateBlockCallback) {
            handleCreation();
          }
        }
      };

      var _iteratorNormalCompletion35 = true;
      var _didIteratorError35 = false;
      var _iteratorError35 = undefined;

      try {
        for (var _iterator35 = this.singletonHandlers[Symbol.iterator](), _step35; !(_iteratorNormalCompletion35 = (_step35 = _iterator35.next()).done); _iteratorNormalCompletion35 = true) {
          var singletonHandler = _step35.value;

          _loop3(singletonHandler);
        }
      } catch (err) {
        _didIteratorError35 = true;
        _iteratorError35 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion35 && _iterator35.return) {
            _iterator35.return();
          }
        } finally {
          if (_didIteratorError35) {
            throw _iteratorError35;
          }
        }
      }
    }
  }]);

  return SFSingletonManager;
}();

; // SFStorageManager should be subclassed, and all the methods below overwritten.

var SFStorageManager = exports.SFStorageManager = function () {
  function SFStorageManager() {
    _classCallCheck(this, SFStorageManager);
  }

  _createClass(SFStorageManager, [{
    key: "setItem",


    /* Simple Key/Value Storage */

    value: function () {
      var _ref72 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee63(key, value) {
        return regeneratorRuntime.wrap(function _callee63$(_context63) {
          while (1) {
            switch (_context63.prev = _context63.next) {
              case 0:
              case "end":
                return _context63.stop();
            }
          }
        }, _callee63, this);
      }));

      function setItem(_x89, _x90) {
        return _ref72.apply(this, arguments);
      }

      return setItem;
    }()
  }, {
    key: "getItem",
    value: function () {
      var _ref73 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee64(key) {
        return regeneratorRuntime.wrap(function _callee64$(_context64) {
          while (1) {
            switch (_context64.prev = _context64.next) {
              case 0:
              case "end":
                return _context64.stop();
            }
          }
        }, _callee64, this);
      }));

      function getItem(_x91) {
        return _ref73.apply(this, arguments);
      }

      return getItem;
    }()
  }, {
    key: "removeItem",
    value: function () {
      var _ref74 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee65(key) {
        return regeneratorRuntime.wrap(function _callee65$(_context65) {
          while (1) {
            switch (_context65.prev = _context65.next) {
              case 0:
              case "end":
                return _context65.stop();
            }
          }
        }, _callee65, this);
      }));

      function removeItem(_x92) {
        return _ref74.apply(this, arguments);
      }

      return removeItem;
    }()
  }, {
    key: "clear",
    value: function () {
      var _ref75 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee66() {
        return regeneratorRuntime.wrap(function _callee66$(_context66) {
          while (1) {
            switch (_context66.prev = _context66.next) {
              case 0:
              case "end":
                return _context66.stop();
            }
          }
        }, _callee66, this);
      }));

      function clear() {
        return _ref75.apply(this, arguments);
      }

      return clear;
    }()
  }, {
    key: "getAllModels",


    /*
    Model Storage
    */

    value: function () {
      var _ref76 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee67() {
        return regeneratorRuntime.wrap(function _callee67$(_context67) {
          while (1) {
            switch (_context67.prev = _context67.next) {
              case 0:
              case "end":
                return _context67.stop();
            }
          }
        }, _callee67, this);
      }));

      function getAllModels() {
        return _ref76.apply(this, arguments);
      }

      return getAllModels;
    }()
  }, {
    key: "saveModel",
    value: function () {
      var _ref77 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee68(item) {
        return regeneratorRuntime.wrap(function _callee68$(_context68) {
          while (1) {
            switch (_context68.prev = _context68.next) {
              case 0:
                return _context68.abrupt("return", this.saveModels([item]));

              case 1:
              case "end":
                return _context68.stop();
            }
          }
        }, _callee68, this);
      }));

      function saveModel(_x93) {
        return _ref77.apply(this, arguments);
      }

      return saveModel;
    }()
  }, {
    key: "saveModels",
    value: function () {
      var _ref78 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee69(items) {
        return regeneratorRuntime.wrap(function _callee69$(_context69) {
          while (1) {
            switch (_context69.prev = _context69.next) {
              case 0:
              case "end":
                return _context69.stop();
            }
          }
        }, _callee69, this);
      }));

      function saveModels(_x94) {
        return _ref78.apply(this, arguments);
      }

      return saveModels;
    }()
  }, {
    key: "deleteModel",
    value: function () {
      var _ref79 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee70(item) {
        return regeneratorRuntime.wrap(function _callee70$(_context70) {
          while (1) {
            switch (_context70.prev = _context70.next) {
              case 0:
              case "end":
                return _context70.stop();
            }
          }
        }, _callee70, this);
      }));

      function deleteModel(_x95) {
        return _ref79.apply(this, arguments);
      }

      return deleteModel;
    }()
  }, {
    key: "clearAllModels",
    value: function () {
      var _ref80 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee71() {
        return regeneratorRuntime.wrap(function _callee71$(_context71) {
          while (1) {
            switch (_context71.prev = _context71.next) {
              case 0:
              case "end":
                return _context71.stop();
            }
          }
        }, _callee71, this);
      }));

      function clearAllModels() {
        return _ref80.apply(this, arguments);
      }

      return clearAllModels;
    }()
  }, {
    key: "clearAllData",


    /* General */

    value: function () {
      var _ref81 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee72() {
        return regeneratorRuntime.wrap(function _callee72$(_context72) {
          while (1) {
            switch (_context72.prev = _context72.next) {
              case 0:
                return _context72.abrupt("return", Promise.all([this.clear(), this.clearAllModels()]));

              case 1:
              case "end":
                return _context72.stop();
            }
          }
        }, _callee72, this);
      }));

      function clearAllData() {
        return _ref81.apply(this, arguments);
      }

      return clearAllData;
    }()
  }]);

  return SFStorageManager;
}();

;
var SFSyncManager = exports.SFSyncManager = function () {
  function SFSyncManager(modelManager, storageManager, httpManager, timeout, interval) {
    _classCallCheck(this, SFSyncManager);

    SFSyncManager.KeyRequestLoadLocal = "KeyRequestLoadLocal";
    SFSyncManager.KeyRequestSaveLocal = "KeyRequestSaveLocal";
    SFSyncManager.KeyRequestLoadSaveAccount = "KeyRequestLoadSaveAccount";

    this.httpManager = httpManager;
    this.modelManager = modelManager;
    this.storageManager = storageManager;

    // Allows you to et your own interval/timeout function (i.e if you're using angular and want to use $timeout)
    this.$interval = interval || setInterval.bind(window);
    this.$timeout = timeout || setTimeout.bind(window);

    this.syncStatus = {};
    this.syncStatusObservers = [];
    this.eventHandlers = [];

    // this.loggingEnabled = true;

    this.PerSyncItemUploadLimit = 150;
    this.ServerItemDownloadLimit = 150;

    // The number of changed items that constitute a major change
    // This is used by the desktop app to create backups
    this.MajorDataChangeThreshold = 15;

    // Sync integrity checking
    // If X consective sync requests return mismatching hashes, then we officially enter out-of-sync.
    this.MaxDiscordanceBeforeOutOfSync = 5;

    // How many consective sync results have had mismatching hashes. This value can never exceed this.MaxDiscordanceBeforeOutOfSync.
    this.syncDiscordance = 0;
    this.outOfSync = false;
  }

  _createClass(SFSyncManager, [{
    key: "handleServerIntegrityHash",
    value: function () {
      var _ref82 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee73(serverHash) {
        var localHash;
        return regeneratorRuntime.wrap(function _callee73$(_context73) {
          while (1) {
            switch (_context73.prev = _context73.next) {
              case 0:
                if (!(!serverHash || serverHash.length == 0)) {
                  _context73.next = 2;
                  break;
                }

                return _context73.abrupt("return", true);

              case 2:
                _context73.next = 4;
                return this.modelManager.computeDataIntegrityHash();

              case 4:
                localHash = _context73.sent;

                if (localHash) {
                  _context73.next = 7;
                  break;
                }

                return _context73.abrupt("return", true);

              case 7:
                if (!(localHash !== serverHash)) {
                  _context73.next = 13;
                  break;
                }

                this.syncDiscordance++;
                if (this.syncDiscordance >= this.MaxDiscordanceBeforeOutOfSync) {
                  if (!this.outOfSync) {
                    this.outOfSync = true;
                    this.notifyEvent("enter-out-of-sync");
                  }
                }
                return _context73.abrupt("return", false);

              case 13:
                // Integrity matches
                if (this.outOfSync) {
                  this.outOfSync = false;
                  this.notifyEvent("exit-out-of-sync");
                }
                this.syncDiscordance = 0;
                return _context73.abrupt("return", true);

              case 16:
              case "end":
                return _context73.stop();
            }
          }
        }, _callee73, this);
      }));

      function handleServerIntegrityHash(_x96) {
        return _ref82.apply(this, arguments);
      }

      return handleServerIntegrityHash;
    }()
  }, {
    key: "isOutOfSync",
    value: function isOutOfSync() {
      // Once we are outOfSync, it's up to the client to display UI to the user to instruct them
      // to take action. The client should present a reconciliation wizard.
      return this.outOfSync;
    }
  }, {
    key: "getServerURL",
    value: function () {
      var _ref83 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee74() {
        return regeneratorRuntime.wrap(function _callee74$(_context74) {
          while (1) {
            switch (_context74.prev = _context74.next) {
              case 0:
                _context74.next = 2;
                return this.storageManager.getItem("server");

              case 2:
                _context74.t0 = _context74.sent;

                if (_context74.t0) {
                  _context74.next = 5;
                  break;
                }

                _context74.t0 = window._default_sf_server;

              case 5:
                return _context74.abrupt("return", _context74.t0);

              case 6:
              case "end":
                return _context74.stop();
            }
          }
        }, _callee74, this);
      }));

      function getServerURL() {
        return _ref83.apply(this, arguments);
      }

      return getServerURL;
    }()
  }, {
    key: "getSyncURL",
    value: function () {
      var _ref84 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee75() {
        return regeneratorRuntime.wrap(function _callee75$(_context75) {
          while (1) {
            switch (_context75.prev = _context75.next) {
              case 0:
                _context75.next = 2;
                return this.getServerURL();

              case 2:
                _context75.t0 = _context75.sent;
                return _context75.abrupt("return", _context75.t0 + "/items/sync");

              case 4:
              case "end":
                return _context75.stop();
            }
          }
        }, _callee75, this);
      }));

      function getSyncURL() {
        return _ref84.apply(this, arguments);
      }

      return getSyncURL;
    }()
  }, {
    key: "registerSyncStatusObserver",
    value: function registerSyncStatusObserver(callback) {
      var observer = { key: new Date(), callback: callback };
      this.syncStatusObservers.push(observer);
      return observer;
    }
  }, {
    key: "removeSyncStatusObserver",
    value: function removeSyncStatusObserver(observer) {
      _.pull(this.syncStatusObservers, observer);
    }
  }, {
    key: "syncStatusDidChange",
    value: function syncStatusDidChange() {
      var _this18 = this;

      this.syncStatusObservers.forEach(function (observer) {
        observer.callback(_this18.syncStatus);
      });
    }
  }, {
    key: "addEventHandler",
    value: function addEventHandler(handler) {
      /*
      Possible Events:
      sync:completed
      sync:taking-too-long
      sync:updated_token
      sync:error
      major-data-change
      local-data-loaded
      sync-session-invalid
      sync-exception
       */
      this.eventHandlers.push(handler);
      return handler;
    }
  }, {
    key: "removeEventHandler",
    value: function removeEventHandler(handler) {
      _.pull(this.eventHandlers, handler);
    }
  }, {
    key: "notifyEvent",
    value: function notifyEvent(syncEvent, data) {
      var _iteratorNormalCompletion37 = true;
      var _didIteratorError37 = false;
      var _iteratorError37 = undefined;

      try {
        for (var _iterator37 = this.eventHandlers[Symbol.iterator](), _step37; !(_iteratorNormalCompletion37 = (_step37 = _iterator37.next()).done); _iteratorNormalCompletion37 = true) {
          var handler = _step37.value;

          handler(syncEvent, data || {});
        }
      } catch (err) {
        _didIteratorError37 = true;
        _iteratorError37 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion37 && _iterator37.return) {
            _iterator37.return();
          }
        } finally {
          if (_didIteratorError37) {
            throw _iteratorError37;
          }
        }
      }
    }
  }, {
    key: "setKeyRequestHandler",
    value: function setKeyRequestHandler(handler) {
      this.keyRequestHandler = handler;
    }
  }, {
    key: "getActiveKeyInfo",
    value: function () {
      var _ref85 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee76(request) {
        return regeneratorRuntime.wrap(function _callee76$(_context76) {
          while (1) {
            switch (_context76.prev = _context76.next) {
              case 0:
                return _context76.abrupt("return", this.keyRequestHandler(request));

              case 1:
              case "end":
                return _context76.stop();
            }
          }
        }, _callee76, this);
      }));

      function getActiveKeyInfo(_x97) {
        return _ref85.apply(this, arguments);
      }

      return getActiveKeyInfo;
    }()
  }, {
    key: "initialDataLoaded",
    value: function initialDataLoaded() {
      return this._initialDataLoaded === true;
    }
  }, {
    key: "_sortLocalItems",
    value: function _sortLocalItems(items) {
      var _this19 = this;

      return items.sort(function (a, b) {
        var dateResult = new Date(b.updated_at) - new Date(a.updated_at);

        var priorityList = _this19.contentTypeLoadPriority;
        var aPriority = 0,
            bPriority = 0;
        if (priorityList) {
          aPriority = priorityList.indexOf(a.content_type);
          bPriority = priorityList.indexOf(b.content_type);
          if (aPriority == -1) {
            // Not found in list, not prioritized. Set it to max value
            aPriority = priorityList.length;
          }
          if (bPriority == -1) {
            // Not found in list, not prioritized. Set it to max value
            bPriority = priorityList.length;
          }
        }

        if (aPriority == bPriority) {
          return dateResult;
        }

        if (aPriority < bPriority) {
          return -1;
        } else {
          return 1;
        }

        // aPriority < bPriority means a should come first
        return aPriority < bPriority ? -1 : 1;
      });
    }
  }, {
    key: "loadLocalItems",
    value: function () {
      var _ref86 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee78() {
        var _this20 = this;

        var _ref87 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
            incrementalCallback = _ref87.incrementalCallback,
            batchSize = _ref87.batchSize,
            options = _ref87.options;

        var latency;
        return regeneratorRuntime.wrap(function _callee78$(_context78) {
          while (1) {
            switch (_context78.prev = _context78.next) {
              case 0:
                if (!(options && options.simulateHighLatency)) {
                  _context78.next = 4;
                  break;
                }

                latency = options.simulatedLatency || 1000;
                _context78.next = 4;
                return this._awaitSleep(latency);

              case 4:
                if (!this.loadLocalDataPromise) {
                  _context78.next = 6;
                  break;
                }

                return _context78.abrupt("return", this.loadLocalDataPromise);

              case 6:

                if (!batchSize) {
                  batchSize = 100;
                }

                this.loadLocalDataPromise = this.storageManager.getAllModels().then(function (items) {
                  // put most recently updated at beginning, sorted by priority
                  items = _this20._sortLocalItems(items);

                  // Filter out any items that exist in the local model mapping and have a lower dirtied date than the local dirtiedDate.
                  items = items.filter(function (nonDecryptedItem) {
                    var localItem = _this20.modelManager.findItem(nonDecryptedItem.uuid);
                    if (!localItem) {
                      return true;
                    }

                    return new Date(nonDecryptedItem.dirtiedDate) > localItem.dirtiedDate;
                  });

                  // break it up into chunks to make interface more responsive for large item counts
                  var total = items.length;
                  var current = 0;
                  var processed = [];

                  var decryptNext = function () {
                    var _ref88 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee77() {
                      var subitems, processedSubitems;
                      return regeneratorRuntime.wrap(function _callee77$(_context77) {
                        while (1) {
                          switch (_context77.prev = _context77.next) {
                            case 0:
                              subitems = items.slice(current, current + batchSize);
                              _context77.next = 3;
                              return _this20.handleItemsResponse(subitems, null, SFModelManager.MappingSourceLocalRetrieved, SFSyncManager.KeyRequestLoadLocal);

                            case 3:
                              processedSubitems = _context77.sent;

                              processed.push(processedSubitems);

                              current += subitems.length;

                              if (!(current < total)) {
                                _context77.next = 10;
                                break;
                              }

                              return _context77.abrupt("return", new Promise(function (innerResolve, innerReject) {
                                _this20.$timeout(function () {
                                  _this20.notifyEvent("local-data-incremental-load");
                                  incrementalCallback && incrementalCallback(current, total);
                                  decryptNext().then(innerResolve);
                                });
                              }));

                            case 10:
                              // Completed
                              _this20._initialDataLoaded = true;
                              _this20.notifyEvent("local-data-loaded");

                            case 12:
                            case "end":
                              return _context77.stop();
                          }
                        }
                      }, _callee77, _this20);
                    }));

                    return function decryptNext() {
                      return _ref88.apply(this, arguments);
                    };
                  }();

                  return decryptNext();
                });

                return _context78.abrupt("return", this.loadLocalDataPromise);

              case 9:
              case "end":
                return _context78.stop();
            }
          }
        }, _callee78, this);
      }));

      function loadLocalItems() {
        return _ref86.apply(this, arguments);
      }

      return loadLocalItems;
    }()
  }, {
    key: "writeItemsToLocalStorage",
    value: function () {
      var _ref89 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee82(items, offlineOnly) {
        var _this21 = this;

        return regeneratorRuntime.wrap(function _callee82$(_context82) {
          while (1) {
            switch (_context82.prev = _context82.next) {
              case 0:
                if (!(items.length == 0)) {
                  _context82.next = 2;
                  break;
                }

                return _context82.abrupt("return");

              case 2:
                return _context82.abrupt("return", new Promise(function () {
                  var _ref90 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee81(resolve, reject) {
                    var nonDeletedItems, deletedItems, _iteratorNormalCompletion38, _didIteratorError38, _iteratorError38, _iterator38, _step38, item, info, params;

                    return regeneratorRuntime.wrap(function _callee81$(_context81) {
                      while (1) {
                        switch (_context81.prev = _context81.next) {
                          case 0:
                            nonDeletedItems = [], deletedItems = [];
                            _iteratorNormalCompletion38 = true;
                            _didIteratorError38 = false;
                            _iteratorError38 = undefined;
                            _context81.prev = 4;

                            for (_iterator38 = items[Symbol.iterator](); !(_iteratorNormalCompletion38 = (_step38 = _iterator38.next()).done); _iteratorNormalCompletion38 = true) {
                              item = _step38.value;

                              if (item.deleted === true) {
                                deletedItems.push(item);
                              } else {
                                nonDeletedItems.push(item);
                              }
                            }

                            _context81.next = 12;
                            break;

                          case 8:
                            _context81.prev = 8;
                            _context81.t0 = _context81["catch"](4);
                            _didIteratorError38 = true;
                            _iteratorError38 = _context81.t0;

                          case 12:
                            _context81.prev = 12;
                            _context81.prev = 13;

                            if (!_iteratorNormalCompletion38 && _iterator38.return) {
                              _iterator38.return();
                            }

                          case 15:
                            _context81.prev = 15;

                            if (!_didIteratorError38) {
                              _context81.next = 18;
                              break;
                            }

                            throw _iteratorError38;

                          case 18:
                            return _context81.finish(15);

                          case 19:
                            return _context81.finish(12);

                          case 20:
                            if (!(deletedItems.length > 0)) {
                              _context81.next = 23;
                              break;
                            }

                            _context81.next = 23;
                            return Promise.all(deletedItems.map(function () {
                              var _ref91 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee79(deletedItem) {
                                return regeneratorRuntime.wrap(function _callee79$(_context79) {
                                  while (1) {
                                    switch (_context79.prev = _context79.next) {
                                      case 0:
                                        return _context79.abrupt("return", _this21.storageManager.deleteModel(deletedItem));

                                      case 1:
                                      case "end":
                                        return _context79.stop();
                                    }
                                  }
                                }, _callee79, _this21);
                              }));

                              return function (_x103) {
                                return _ref91.apply(this, arguments);
                              };
                            }()));

                          case 23:
                            _context81.next = 25;
                            return _this21.getActiveKeyInfo(SFSyncManager.KeyRequestSaveLocal);

                          case 25:
                            info = _context81.sent;

                            if (!(nonDeletedItems.length > 0)) {
                              _context81.next = 33;
                              break;
                            }

                            _context81.next = 29;
                            return Promise.all(nonDeletedItems.map(function () {
                              var _ref92 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee80(item) {
                                var itemParams;
                                return regeneratorRuntime.wrap(function _callee80$(_context80) {
                                  while (1) {
                                    switch (_context80.prev = _context80.next) {
                                      case 0:
                                        itemParams = new SFItemParams(item, info.keys, info.auth_params);
                                        _context80.next = 3;
                                        return itemParams.paramsForLocalStorage();

                                      case 3:
                                        itemParams = _context80.sent;

                                        if (offlineOnly) {
                                          delete itemParams.dirty;
                                        }
                                        return _context80.abrupt("return", itemParams);

                                      case 6:
                                      case "end":
                                        return _context80.stop();
                                    }
                                  }
                                }, _callee80, _this21);
                              }));

                              return function (_x104) {
                                return _ref92.apply(this, arguments);
                              };
                            }())).catch(function (e) {
                              return reject(e);
                            });

                          case 29:
                            params = _context81.sent;
                            _context81.next = 32;
                            return _this21.storageManager.saveModels(params).catch(function (error) {
                              console.error("Error writing items", error);
                              _this21.syncStatus.localError = error;
                              _this21.syncStatusDidChange();
                              reject();
                            });

                          case 32:

                            // on success
                            if (_this21.syncStatus.localError) {
                              _this21.syncStatus.localError = null;
                              _this21.syncStatusDidChange();
                            }

                          case 33:
                            resolve();

                          case 34:
                          case "end":
                            return _context81.stop();
                        }
                      }
                    }, _callee81, _this21, [[4, 8, 12, 20], [13,, 15, 19]]);
                  }));

                  return function (_x101, _x102) {
                    return _ref90.apply(this, arguments);
                  };
                }()));

              case 3:
              case "end":
                return _context82.stop();
            }
          }
        }, _callee82, this);
      }));

      function writeItemsToLocalStorage(_x99, _x100) {
        return _ref89.apply(this, arguments);
      }

      return writeItemsToLocalStorage;
    }()
  }, {
    key: "syncOffline",
    value: function () {
      var _ref93 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee83(items) {
        var _this22 = this;

        var _iteratorNormalCompletion39, _didIteratorError39, _iteratorError39, _iterator39, _step39, item;

        return regeneratorRuntime.wrap(function _callee83$(_context83) {
          while (1) {
            switch (_context83.prev = _context83.next) {
              case 0:
                // Update all items updated_at to now
                _iteratorNormalCompletion39 = true;
                _didIteratorError39 = false;
                _iteratorError39 = undefined;
                _context83.prev = 3;
                for (_iterator39 = items[Symbol.iterator](); !(_iteratorNormalCompletion39 = (_step39 = _iterator39.next()).done); _iteratorNormalCompletion39 = true) {
                  item = _step39.value;
                  item.updated_at = new Date();
                }
                _context83.next = 11;
                break;

              case 7:
                _context83.prev = 7;
                _context83.t0 = _context83["catch"](3);
                _didIteratorError39 = true;
                _iteratorError39 = _context83.t0;

              case 11:
                _context83.prev = 11;
                _context83.prev = 12;

                if (!_iteratorNormalCompletion39 && _iterator39.return) {
                  _iterator39.return();
                }

              case 14:
                _context83.prev = 14;

                if (!_didIteratorError39) {
                  _context83.next = 17;
                  break;
                }

                throw _iteratorError39;

              case 17:
                return _context83.finish(14);

              case 18:
                return _context83.finish(11);

              case 19:
                return _context83.abrupt("return", this.writeItemsToLocalStorage(items, true).then(function (responseItems) {
                  // delete anything needing to be deleted
                  var _iteratorNormalCompletion40 = true;
                  var _didIteratorError40 = false;
                  var _iteratorError40 = undefined;

                  try {
                    for (var _iterator40 = items[Symbol.iterator](), _step40; !(_iteratorNormalCompletion40 = (_step40 = _iterator40.next()).done); _iteratorNormalCompletion40 = true) {
                      var _item = _step40.value;

                      if (_item.deleted) {
                        _this22.modelManager.removeItemLocally(_item);
                      }
                    }
                  } catch (err) {
                    _didIteratorError40 = true;
                    _iteratorError40 = err;
                  } finally {
                    try {
                      if (!_iteratorNormalCompletion40 && _iterator40.return) {
                        _iterator40.return();
                      }
                    } finally {
                      if (_didIteratorError40) {
                        throw _iteratorError40;
                      }
                    }
                  }

                  _this22.modelManager.clearDirtyItems(items);
                  // Required in order for modelManager to notify sync observers
                  _this22.modelManager.didSyncModelsOffline(items);

                  _this22.notifyEvent("sync:completed", { savedItems: items });
                  return { saved_items: items };
                }));

              case 20:
              case "end":
                return _context83.stop();
            }
          }
        }, _callee83, this, [[3, 7, 11, 19], [12,, 14, 18]]);
      }));

      function syncOffline(_x105) {
        return _ref93.apply(this, arguments);
      }

      return syncOffline;
    }()

    /*
      In the case of signing in and merging local data, we alternative UUIDs
      to avoid overwriting data a user may retrieve that has the same UUID.
      Alternating here forces us to to create duplicates of the items instead.
     */

  }, {
    key: "markAllItemsDirtyAndSaveOffline",
    value: function () {
      var _ref94 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee84(alternateUUIDs) {
        var originalItems, _iteratorNormalCompletion41, _didIteratorError41, _iteratorError41, _iterator41, _step41, item, allItems, _iteratorNormalCompletion42, _didIteratorError42, _iteratorError42, _iterator42, _step42, _item2;

        return regeneratorRuntime.wrap(function _callee84$(_context84) {
          while (1) {
            switch (_context84.prev = _context84.next) {
              case 0:

                // use a copy, as alternating uuid will affect array
                originalItems = this.modelManager.allNondummyItems.filter(function (item) {
                  return !item.errorDecrypting;
                }).slice();

                if (!alternateUUIDs) {
                  _context84.next = 28;
                  break;
                }

                _iteratorNormalCompletion41 = true;
                _didIteratorError41 = false;
                _iteratorError41 = undefined;
                _context84.prev = 5;
                _iterator41 = originalItems[Symbol.iterator]();

              case 7:
                if (_iteratorNormalCompletion41 = (_step41 = _iterator41.next()).done) {
                  _context84.next = 14;
                  break;
                }

                item = _step41.value;
                _context84.next = 11;
                return this.modelManager.alternateUUIDForItem(item);

              case 11:
                _iteratorNormalCompletion41 = true;
                _context84.next = 7;
                break;

              case 14:
                _context84.next = 20;
                break;

              case 16:
                _context84.prev = 16;
                _context84.t0 = _context84["catch"](5);
                _didIteratorError41 = true;
                _iteratorError41 = _context84.t0;

              case 20:
                _context84.prev = 20;
                _context84.prev = 21;

                if (!_iteratorNormalCompletion41 && _iterator41.return) {
                  _iterator41.return();
                }

              case 23:
                _context84.prev = 23;

                if (!_didIteratorError41) {
                  _context84.next = 26;
                  break;
                }

                throw _iteratorError41;

              case 26:
                return _context84.finish(23);

              case 27:
                return _context84.finish(20);

              case 28:
                allItems = this.modelManager.allNondummyItems;
                _iteratorNormalCompletion42 = true;
                _didIteratorError42 = false;
                _iteratorError42 = undefined;
                _context84.prev = 32;

                for (_iterator42 = allItems[Symbol.iterator](); !(_iteratorNormalCompletion42 = (_step42 = _iterator42.next()).done); _iteratorNormalCompletion42 = true) {
                  _item2 = _step42.value;
                  _item2.setDirty(true);
                }
                _context84.next = 40;
                break;

              case 36:
                _context84.prev = 36;
                _context84.t1 = _context84["catch"](32);
                _didIteratorError42 = true;
                _iteratorError42 = _context84.t1;

              case 40:
                _context84.prev = 40;
                _context84.prev = 41;

                if (!_iteratorNormalCompletion42 && _iterator42.return) {
                  _iterator42.return();
                }

              case 43:
                _context84.prev = 43;

                if (!_didIteratorError42) {
                  _context84.next = 46;
                  break;
                }

                throw _iteratorError42;

              case 46:
                return _context84.finish(43);

              case 47:
                return _context84.finish(40);

              case 48:
                return _context84.abrupt("return", this.writeItemsToLocalStorage(allItems, false));

              case 49:
              case "end":
                return _context84.stop();
            }
          }
        }, _callee84, this, [[5, 16, 20, 28], [21,, 23, 27], [32, 36, 40, 48], [41,, 43, 47]]);
      }));

      function markAllItemsDirtyAndSaveOffline(_x106) {
        return _ref94.apply(this, arguments);
      }

      return markAllItemsDirtyAndSaveOffline;
    }()
  }, {
    key: "setSyncToken",
    value: function () {
      var _ref95 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee85(token) {
        return regeneratorRuntime.wrap(function _callee85$(_context85) {
          while (1) {
            switch (_context85.prev = _context85.next) {
              case 0:
                this._syncToken = token;
                _context85.next = 3;
                return this.storageManager.setItem("syncToken", token);

              case 3:
              case "end":
                return _context85.stop();
            }
          }
        }, _callee85, this);
      }));

      function setSyncToken(_x107) {
        return _ref95.apply(this, arguments);
      }

      return setSyncToken;
    }()
  }, {
    key: "getSyncToken",
    value: function () {
      var _ref96 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee86() {
        return regeneratorRuntime.wrap(function _callee86$(_context86) {
          while (1) {
            switch (_context86.prev = _context86.next) {
              case 0:
                if (this._syncToken) {
                  _context86.next = 4;
                  break;
                }

                _context86.next = 3;
                return this.storageManager.getItem("syncToken");

              case 3:
                this._syncToken = _context86.sent;

              case 4:
                return _context86.abrupt("return", this._syncToken);

              case 5:
              case "end":
                return _context86.stop();
            }
          }
        }, _callee86, this);
      }));

      function getSyncToken() {
        return _ref96.apply(this, arguments);
      }

      return getSyncToken;
    }()
  }, {
    key: "setCursorToken",
    value: function () {
      var _ref97 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee87(token) {
        return regeneratorRuntime.wrap(function _callee87$(_context87) {
          while (1) {
            switch (_context87.prev = _context87.next) {
              case 0:
                this._cursorToken = token;

                if (!token) {
                  _context87.next = 6;
                  break;
                }

                _context87.next = 4;
                return this.storageManager.setItem("cursorToken", token);

              case 4:
                _context87.next = 8;
                break;

              case 6:
                _context87.next = 8;
                return this.storageManager.removeItem("cursorToken");

              case 8:
              case "end":
                return _context87.stop();
            }
          }
        }, _callee87, this);
      }));

      function setCursorToken(_x108) {
        return _ref97.apply(this, arguments);
      }

      return setCursorToken;
    }()
  }, {
    key: "getCursorToken",
    value: function () {
      var _ref98 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee88() {
        return regeneratorRuntime.wrap(function _callee88$(_context88) {
          while (1) {
            switch (_context88.prev = _context88.next) {
              case 0:
                if (this._cursorToken) {
                  _context88.next = 4;
                  break;
                }

                _context88.next = 3;
                return this.storageManager.getItem("cursorToken");

              case 3:
                this._cursorToken = _context88.sent;

              case 4:
                return _context88.abrupt("return", this._cursorToken);

              case 5:
              case "end":
                return _context88.stop();
            }
          }
        }, _callee88, this);
      }));

      function getCursorToken() {
        return _ref98.apply(this, arguments);
      }

      return getCursorToken;
    }()
  }, {
    key: "clearQueuedCallbacks",
    value: function clearQueuedCallbacks() {
      this._queuedCallbacks = [];
    }
  }, {
    key: "callQueuedCallbacks",
    value: function callQueuedCallbacks(response) {
      var allCallbacks = this.queuedCallbacks;
      if (allCallbacks.length) {
        var _iteratorNormalCompletion43 = true;
        var _didIteratorError43 = false;
        var _iteratorError43 = undefined;

        try {
          for (var _iterator43 = allCallbacks[Symbol.iterator](), _step43; !(_iteratorNormalCompletion43 = (_step43 = _iterator43.next()).done); _iteratorNormalCompletion43 = true) {
            var eachCallback = _step43.value;

            eachCallback(response);
          }
        } catch (err) {
          _didIteratorError43 = true;
          _iteratorError43 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion43 && _iterator43.return) {
              _iterator43.return();
            }
          } finally {
            if (_didIteratorError43) {
              throw _iteratorError43;
            }
          }
        }

        this.clearQueuedCallbacks();
      }
    }
  }, {
    key: "beginCheckingIfSyncIsTakingTooLong",
    value: function beginCheckingIfSyncIsTakingTooLong() {
      if (this.syncStatus.checker) {
        this.stopCheckingIfSyncIsTakingTooLong();
      }
      this.syncStatus.checker = this.$interval(function () {
        // check to see if the ongoing sync is taking too long, alert the user
        var secondsPassed = (new Date() - this.syncStatus.syncStart) / 1000;
        var warningThreshold = 5.0; // seconds
        if (secondsPassed > warningThreshold) {
          this.notifyEvent("sync:taking-too-long");
          this.stopCheckingIfSyncIsTakingTooLong();
        }
      }.bind(this), 500);
    }
  }, {
    key: "stopCheckingIfSyncIsTakingTooLong",
    value: function stopCheckingIfSyncIsTakingTooLong() {
      if (this.$interval.hasOwnProperty("cancel")) {
        this.$interval.cancel(this.syncStatus.checker);
      } else {
        clearInterval(this.syncStatus.checker);
      }
      this.syncStatus.checker = null;
    }
  }, {
    key: "lockSyncing",
    value: function lockSyncing() {
      this.syncLocked = true;
    }
  }, {
    key: "unlockSyncing",
    value: function unlockSyncing() {
      this.syncLocked = false;
    }
  }, {
    key: "sync",
    value: function () {
      var _ref99 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee90() {
        var _this23 = this;

        var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
        return regeneratorRuntime.wrap(function _callee90$(_context90) {
          while (1) {
            switch (_context90.prev = _context90.next) {
              case 0:
                if (!this.syncLocked) {
                  _context90.next = 3;
                  break;
                }

                console.log("Sync Locked, Returning;");
                return _context90.abrupt("return");

              case 3:
                return _context90.abrupt("return", new Promise(function () {
                  var _ref100 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee89(resolve, reject) {
                    var allDirtyItems, dirtyItemsNotYetSaved, info, isSyncInProgress, initialDataLoaded, isContinuationSync, submitLimit, subItems, params, _iteratorNormalCompletion44, _didIteratorError44, _iteratorError44, _iterator44, _step44, item;

                    return regeneratorRuntime.wrap(function _callee89$(_context89) {
                      while (1) {
                        switch (_context89.prev = _context89.next) {
                          case 0:

                            if (!options) options = {};

                            allDirtyItems = _this23.modelManager.getDirtyItems();
                            dirtyItemsNotYetSaved = allDirtyItems.filter(function (candidate) {
                              return !_this23.lastDirtyItemsSave || candidate.dirtiedDate > _this23.lastDirtyItemsSave;
                            });
                            _context89.next = 5;
                            return _this23.getActiveKeyInfo(SFSyncManager.KeyRequestLoadSaveAccount);

                          case 5:
                            info = _context89.sent;
                            isSyncInProgress = _this23.syncStatus.syncOpInProgress;
                            initialDataLoaded = _this23.initialDataLoaded();

                            if (!(isSyncInProgress || !initialDataLoaded)) {
                              _context89.next = 16;
                              break;
                            }

                            _this23.performSyncAgainOnCompletion = true;
                            _this23.lastDirtyItemsSave = new Date();
                            _context89.next = 13;
                            return _this23.writeItemsToLocalStorage(dirtyItemsNotYetSaved, false);

                          case 13:
                            if (isSyncInProgress) {
                              _this23.queuedCallbacks.push(resolve);
                              console.warn("Attempting to sync while existing sync is in progress.");
                            }
                            if (!initialDataLoaded) {
                              console.warn("(1) Attempting to perform online sync before local data has loaded");
                              // Resolve right away, as we can't be sure when local data will be called by consumer.
                              resolve();
                            }
                            return _context89.abrupt("return");

                          case 16:

                            // Set this value immediately after checking it above, to avoid race conditions.
                            _this23.syncStatus.syncOpInProgress = true;

                            if (!info.offline) {
                              _context89.next = 19;
                              break;
                            }

                            return _context89.abrupt("return", _this23.syncOffline(allDirtyItems).then(function (response) {
                              _this23.syncStatus.syncOpInProgress = false;
                              resolve(response);
                            }).catch(function (e) {
                              _this23.notifyEvent("sync-exception", e);
                            }));

                          case 19:
                            if (_this23.initialDataLoaded()) {
                              _context89.next = 22;
                              break;
                            }

                            console.error("(2) Attempting to perform online sync before local data has loaded");
                            return _context89.abrupt("return");

                          case 22:

                            if (_this23.loggingEnabled) {
                              console.log("Syncing online user.");
                            }

                            isContinuationSync = _this23.syncStatus.needsMoreSync;

                            _this23.syncStatus.syncStart = new Date();
                            _this23.beginCheckingIfSyncIsTakingTooLong();

                            submitLimit = _this23.PerSyncItemUploadLimit;
                            subItems = allDirtyItems.slice(0, submitLimit);

                            if (subItems.length < allDirtyItems.length) {
                              // more items left to be synced, repeat
                              _this23.syncStatus.needsMoreSync = true;
                            } else {
                              _this23.syncStatus.needsMoreSync = false;
                            }

                            if (!isContinuationSync) {
                              _this23.syncStatus.total = allDirtyItems.length;
                              _this23.syncStatus.current = 0;
                            }

                            // If items are marked as dirty during a long running sync request, total isn't updated
                            // This happens mostly in the case of large imports and sync conflicts where duplicated items are created
                            if (_this23.syncStatus.current > _this23.syncStatus.total) {
                              _this23.syncStatus.total = _this23.syncStatus.current;
                            }

                            _this23.syncStatusDidChange();

                            // Perform save after you've updated all status signals above. Presync save can take several seconds in some cases.
                            // Write to local storage before beginning sync.
                            // This way, if they close the browser before the sync request completes, local changes will not be lost
                            _context89.next = 34;
                            return _this23.writeItemsToLocalStorage(dirtyItemsNotYetSaved, false);

                          case 34:
                            _this23.lastDirtyItemsSave = new Date();

                            if (options.onPreSyncSave) {
                              options.onPreSyncSave();
                            }

                            // when doing a sync request that returns items greater than the limit, and thus subsequent syncs are required,
                            // we want to keep track of all retreived items, then save to local storage only once all items have been retrieved,
                            // so that relationships remain intact
                            // Update 12/18: I don't think we need to do this anymore, since relationships will now retroactively resolve their relationships,
                            // if an item they were looking for hasn't been pulled in yet.
                            if (!_this23.allRetreivedItems) {
                              _this23.allRetreivedItems = [];
                            }

                            // We also want to do this for savedItems
                            if (!_this23.allSavedItems) {
                              _this23.allSavedItems = [];
                            }

                            params = {};

                            params.limit = _this23.ServerItemDownloadLimit;

                            if (options.performIntegrityCheck) {
                              params.compute_integrity = true;
                            }

                            _context89.prev = 41;
                            _context89.next = 44;
                            return Promise.all(subItems.map(function (item) {
                              var itemParams = new SFItemParams(item, info.keys, info.auth_params);
                              itemParams.additionalFields = options.additionalFields;
                              return itemParams.paramsForSync();
                            })).then(function (itemsParams) {
                              params.items = itemsParams;
                            });

                          case 44:
                            _context89.next = 49;
                            break;

                          case 46:
                            _context89.prev = 46;
                            _context89.t0 = _context89["catch"](41);

                            _this23.notifyEvent("sync-exception", _context89.t0);

                          case 49:
                            _iteratorNormalCompletion44 = true;
                            _didIteratorError44 = false;
                            _iteratorError44 = undefined;
                            _context89.prev = 52;


                            for (_iterator44 = subItems[Symbol.iterator](); !(_iteratorNormalCompletion44 = (_step44 = _iterator44.next()).done); _iteratorNormalCompletion44 = true) {
                              item = _step44.value;

                              // Reset dirty counter to 0, since we're about to sync it.
                              // This means anyone marking the item as dirty after this will cause it so sync again and not be cleared on sync completion.
                              item.dirtyCount = 0;
                            }

                            _context89.next = 60;
                            break;

                          case 56:
                            _context89.prev = 56;
                            _context89.t1 = _context89["catch"](52);
                            _didIteratorError44 = true;
                            _iteratorError44 = _context89.t1;

                          case 60:
                            _context89.prev = 60;
                            _context89.prev = 61;

                            if (!_iteratorNormalCompletion44 && _iterator44.return) {
                              _iterator44.return();
                            }

                          case 63:
                            _context89.prev = 63;

                            if (!_didIteratorError44) {
                              _context89.next = 66;
                              break;
                            }

                            throw _iteratorError44;

                          case 66:
                            return _context89.finish(63);

                          case 67:
                            return _context89.finish(60);

                          case 68:
                            _context89.next = 70;
                            return _this23.getSyncToken();

                          case 70:
                            params.sync_token = _context89.sent;
                            _context89.next = 73;
                            return _this23.getCursorToken();

                          case 73:
                            params.cursor_token = _context89.sent;
                            _context89.prev = 74;
                            _context89.t2 = _this23.httpManager;
                            _context89.next = 78;
                            return _this23.getSyncURL();

                          case 78:
                            _context89.t3 = _context89.sent;
                            _context89.t4 = params;

                            _context89.t5 = function (response) {
                              _this23.handleSyncSuccess(subItems, response, options).then(function () {
                                resolve(response);
                              }).catch(function (e) {
                                console.log("Caught sync success exception:", e);
                                _this23.handleSyncError(null, null, allDirtyItems).then(function (errorResponse) {
                                  resolve(errorResponse);
                                });
                              });
                            };

                            _context89.t6 = function (response, statusCode) {
                              _this23.handleSyncError(response, statusCode, allDirtyItems).then(function (errorResponse) {
                                resolve(errorResponse);
                              });
                            };

                            _context89.t2.postAbsolute.call(_context89.t2, _context89.t3, _context89.t4, _context89.t5, _context89.t6);

                            _context89.next = 88;
                            break;

                          case 85:
                            _context89.prev = 85;
                            _context89.t7 = _context89["catch"](74);

                            console.log("Sync exception caught:", _context89.t7);

                          case 88:
                          case "end":
                            return _context89.stop();
                        }
                      }
                    }, _callee89, _this23, [[41, 46], [52, 56, 60, 68], [61,, 63, 67], [74, 85]]);
                  }));

                  return function (_x110, _x111) {
                    return _ref100.apply(this, arguments);
                  };
                }()));

              case 4:
              case "end":
                return _context90.stop();
            }
          }
        }, _callee90, this);
      }));

      function sync() {
        return _ref99.apply(this, arguments);
      }

      return sync;
    }()
  }, {
    key: "_awaitSleep",
    value: function () {
      var _ref101 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee91(durationInMs) {
        return regeneratorRuntime.wrap(function _callee91$(_context91) {
          while (1) {
            switch (_context91.prev = _context91.next) {
              case 0:
                console.warn("Simulating high latency sync request", durationInMs);
                return _context91.abrupt("return", new Promise(function (resolve, reject) {
                  setTimeout(function () {
                    resolve();
                  }, durationInMs);
                }));

              case 2:
              case "end":
                return _context91.stop();
            }
          }
        }, _callee91, this);
      }));

      function _awaitSleep(_x112) {
        return _ref101.apply(this, arguments);
      }

      return _awaitSleep;
    }()
  }, {
    key: "handleSyncSuccess",
    value: function () {
      var _ref102 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee92(syncedItems, response, options) {
        var _this24 = this;

        var latency, allSavedUUIDs, currentRequestSavedUUIDs, itemsToClearAsDirty, _iteratorNormalCompletion45, _didIteratorError45, _iteratorError45, _iterator45, _step45, item, retrieved, omitFields, saved, deprecated_unsaved, conflicts, conflictsNeedSync, matches, cursorToken;

        return regeneratorRuntime.wrap(function _callee92$(_context92) {
          while (1) {
            switch (_context92.prev = _context92.next) {
              case 0:
                if (!options.simulateHighLatency) {
                  _context92.next = 4;
                  break;
                }

                latency = options.simulatedLatency || 1000;
                _context92.next = 4;
                return this._awaitSleep(latency);

              case 4:

                this.syncStatus.error = null;

                if (this.loggingEnabled) {
                  console.log("Sync response", response);
                }

                allSavedUUIDs = this.allSavedItems.map(function (item) {
                  return item.uuid;
                });
                currentRequestSavedUUIDs = response.saved_items.map(function (savedResponse) {
                  return savedResponse.uuid;
                });


                response.retrieved_items = response.retrieved_items.filter(function (retrievedItem) {
                  var isInPreviousSaved = allSavedUUIDs.includes(retrievedItem.uuid);
                  var isInCurrentSaved = currentRequestSavedUUIDs.includes(retrievedItem.uuid);
                  if (isInPreviousSaved || isInCurrentSaved) {
                    return false;
                  }

                  var localItem = _this24.modelManager.findItem(retrievedItem.uuid);
                  if (localItem && localItem.dirty) {
                    return false;
                  }
                  return true;
                });

                // Clear dirty items after we've finish filtering retrieved_items above, since that depends on dirty items.
                // Check to make sure any subItem hasn't been marked as dirty again while a sync was ongoing
                itemsToClearAsDirty = [];
                _iteratorNormalCompletion45 = true;
                _didIteratorError45 = false;
                _iteratorError45 = undefined;
                _context92.prev = 13;

                for (_iterator45 = syncedItems[Symbol.iterator](); !(_iteratorNormalCompletion45 = (_step45 = _iterator45.next()).done); _iteratorNormalCompletion45 = true) {
                  item = _step45.value;

                  if (item.dirtyCount == 0) {
                    // Safe to clear as dirty
                    itemsToClearAsDirty.push(item);
                  }
                }

                _context92.next = 21;
                break;

              case 17:
                _context92.prev = 17;
                _context92.t0 = _context92["catch"](13);
                _didIteratorError45 = true;
                _iteratorError45 = _context92.t0;

              case 21:
                _context92.prev = 21;
                _context92.prev = 22;

                if (!_iteratorNormalCompletion45 && _iterator45.return) {
                  _iterator45.return();
                }

              case 24:
                _context92.prev = 24;

                if (!_didIteratorError45) {
                  _context92.next = 27;
                  break;
                }

                throw _iteratorError45;

              case 27:
                return _context92.finish(24);

              case 28:
                return _context92.finish(21);

              case 29:
                this.modelManager.clearDirtyItems(itemsToClearAsDirty);

                // Map retrieved items to local data
                // Note that deleted items will not be returned
                _context92.next = 32;
                return this.handleItemsResponse(response.retrieved_items, null, SFModelManager.MappingSourceRemoteRetrieved, SFSyncManager.KeyRequestLoadSaveAccount);

              case 32:
                retrieved = _context92.sent;


                // Append items to master list of retrieved items for this ongoing sync operation
                this.allRetreivedItems = this.allRetreivedItems.concat(retrieved);
                this.syncStatus.retrievedCount = this.allRetreivedItems.length;

                // Merge only metadata for saved items
                // we write saved items to disk now because it clears their dirty status then saves
                // if we saved items before completion, we had have to save them as dirty and save them again on success as clean
                omitFields = ["content", "auth_hash"];

                // Map saved items to local data

                _context92.next = 38;
                return this.handleItemsResponse(response.saved_items, omitFields, SFModelManager.MappingSourceRemoteSaved, SFSyncManager.KeyRequestLoadSaveAccount);

              case 38:
                saved = _context92.sent;


                // Append items to master list of saved items for this ongoing sync operation
                this.allSavedItems = this.allSavedItems.concat(saved);

                // 'unsaved' is deprecated and replaced with 'conflicts' in newer version.
                deprecated_unsaved = response.unsaved;
                _context92.next = 43;
                return this.deprecated_handleUnsavedItemsResponse(deprecated_unsaved);

              case 43:
                _context92.next = 45;
                return this.handleConflictsResponse(response.conflicts);

              case 45:
                conflicts = _context92.sent;
                conflictsNeedSync = conflicts && conflicts.length > 0;

                if (!conflicts) {
                  _context92.next = 50;
                  break;
                }

                _context92.next = 50;
                return this.writeItemsToLocalStorage(conflicts, false);

              case 50:
                _context92.next = 52;
                return this.writeItemsToLocalStorage(saved, false);

              case 52:
                _context92.next = 54;
                return this.writeItemsToLocalStorage(retrieved, false);

              case 54:
                if (!(response.integrity_hash && !response.cursor_token)) {
                  _context92.next = 59;
                  break;
                }

                _context92.next = 57;
                return this.handleServerIntegrityHash(response.integrity_hash);

              case 57:
                matches = _context92.sent;

                if (!matches) {
                  // If the server hash doesn't match our local hash, we want to continue syncing until we reach
                  // the max discordance threshold
                  if (this.syncDiscordance < this.MaxDiscordanceBeforeOutOfSync) {
                    this.performSyncAgainOnCompletion = true;
                  }
                }

              case 59:

                this.syncStatus.syncOpInProgress = false;
                this.syncStatus.current += syncedItems.length;

                this.syncStatusDidChange();

                // set the sync token at the end, so that if any errors happen above, you can resync
                this.setSyncToken(response.sync_token);
                this.setCursorToken(response.cursor_token);

                this.stopCheckingIfSyncIsTakingTooLong();

                _context92.next = 67;
                return this.getCursorToken();

              case 67:
                cursorToken = _context92.sent;

                if (!(cursorToken || this.syncStatus.needsMoreSync)) {
                  _context92.next = 72;
                  break;
                }

                return _context92.abrupt("return", new Promise(function (resolve, reject) {
                  setTimeout(function () {
                    this.sync(options).then(resolve);
                  }.bind(_this24), 10); // wait 10ms to allow UI to update
                }));

              case 72:
                if (!conflictsNeedSync) {
                  _context92.next = 77;
                  break;
                }

                // We'll use the conflict sync as the next sync, so performSyncAgainOnCompletion can be turned off.
                this.performSyncAgainOnCompletion = false;
                // Include as part of await/resolve chain
                return _context92.abrupt("return", new Promise(function (resolve, reject) {
                  setTimeout(function () {
                    _this24.sync(options).then(resolve);
                  }, 10); // wait 10ms to allow UI to update
                }));

              case 77:
                this.syncStatus.retrievedCount = 0;
                this.syncStatusDidChange();

                if (this.allRetreivedItems.length >= this.majorDataChangeThreshold || saved.length >= this.majorDataChangeThreshold || deprecated_unsaved && deprecated_unsaved.length >= this.majorDataChangeThreshold || conflicts && conflicts.length >= this.majorDataChangeThreshold) {
                  this.notifyEvent("major-data-change");
                }

                this.callQueuedCallbacks(response);
                this.notifyEvent("sync:completed", { retrievedItems: this.allRetreivedItems, savedItems: this.allSavedItems });

                this.allRetreivedItems = [];
                this.allSavedItems = [];

                if (this.performSyncAgainOnCompletion) {
                  this.performSyncAgainOnCompletion = false;
                  setTimeout(function () {
                    _this24.sync(options);
                  }, 10); // wait 10ms to allow UI to update
                }

                return _context92.abrupt("return", response);

              case 86:
              case "end":
                return _context92.stop();
            }
          }
        }, _callee92, this, [[13, 17, 21, 29], [22,, 24, 28]]);
      }));

      function handleSyncSuccess(_x113, _x114, _x115) {
        return _ref102.apply(this, arguments);
      }

      return handleSyncSuccess;
    }()
  }, {
    key: "handleSyncError",
    value: function () {
      var _ref103 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee93(response, statusCode, allDirtyItems) {
        return regeneratorRuntime.wrap(function _callee93$(_context93) {
          while (1) {
            switch (_context93.prev = _context93.next) {
              case 0:
                console.log("Sync error: ", response);

                if (statusCode == 401) {
                  this.notifyEvent("sync-session-invalid");
                }

                if (!response) {
                  response = { error: { message: "Could not connect to server." } };
                } else if (typeof response == 'string') {
                  response = { error: { message: response } };
                }

                this.syncStatus.syncOpInProgress = false;
                this.syncStatus.error = response.error;
                this.syncStatusDidChange();

                this.writeItemsToLocalStorage(allDirtyItems, false);
                this.modelManager.didSyncModelsOffline(allDirtyItems);

                this.stopCheckingIfSyncIsTakingTooLong();

                this.notifyEvent("sync:error", response.error);

                this.callQueuedCallbacks({ error: "Sync error" });

                return _context93.abrupt("return", response);

              case 12:
              case "end":
                return _context93.stop();
            }
          }
        }, _callee93, this);
      }));

      function handleSyncError(_x116, _x117, _x118) {
        return _ref103.apply(this, arguments);
      }

      return handleSyncError;
    }()
  }, {
    key: "handleItemsResponse",
    value: function () {
      var _ref104 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee94(responseItems, omitFields, source, keyRequest) {
        var keys, items, itemsWithErrorStatusChange;
        return regeneratorRuntime.wrap(function _callee94$(_context94) {
          while (1) {
            switch (_context94.prev = _context94.next) {
              case 0:
                _context94.next = 2;
                return this.getActiveKeyInfo(keyRequest);

              case 2:
                keys = _context94.sent.keys;
                _context94.next = 5;
                return SFJS.itemTransformer.decryptMultipleItems(responseItems, keys);

              case 5:
                items = this.modelManager.mapResponseItemsToLocalModelsOmittingFields(responseItems, omitFields, source);

                // During the decryption process, items may be marked as "errorDecrypting". If so, we want to be sure
                // to persist this new state by writing these items back to local storage. When an item's "errorDecrypting"
                // flag is changed, its "errorDecryptingValueChanged" flag will be set, so we can find these items by filtering (then unsetting) below:

                itemsWithErrorStatusChange = items.filter(function (item) {
                  var valueChanged = item.errorDecryptingValueChanged;
                  // unset after consuming value
                  item.errorDecryptingValueChanged = false;
                  return valueChanged;
                });

                if (itemsWithErrorStatusChange.length > 0) {
                  this.writeItemsToLocalStorage(itemsWithErrorStatusChange, false);
                }

                return _context94.abrupt("return", items);

              case 9:
              case "end":
                return _context94.stop();
            }
          }
        }, _callee94, this);
      }));

      function handleItemsResponse(_x119, _x120, _x121, _x122) {
        return _ref104.apply(this, arguments);
      }

      return handleItemsResponse;
    }()
  }, {
    key: "refreshErroredItems",
    value: function () {
      var _ref105 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee95() {
        var erroredItems;
        return regeneratorRuntime.wrap(function _callee95$(_context95) {
          while (1) {
            switch (_context95.prev = _context95.next) {
              case 0:
                erroredItems = this.modelManager.allNondummyItems.filter(function (item) {
                  return item.errorDecrypting == true;
                });

                if (!(erroredItems.length > 0)) {
                  _context95.next = 3;
                  break;
                }

                return _context95.abrupt("return", this.handleItemsResponse(erroredItems, null, SFModelManager.MappingSourceLocalRetrieved, SFSyncManager.KeyRequestLoadSaveAccount));

              case 3:
              case "end":
                return _context95.stop();
            }
          }
        }, _callee95, this);
      }));

      function refreshErroredItems() {
        return _ref105.apply(this, arguments);
      }

      return refreshErroredItems;
    }()

    /*
    The difference between 'unsaved' (deprecated_handleUnsavedItemsResponse) and 'conflicts' (handleConflictsResponse) is that
    with unsaved items, the local copy is triumphant on the server, and we check the server copy to see if we should
    create it as a duplicate. This is for the legacy API where it would save what you sent the server no matter its value,
    and the client would decide what to do with the previous server value.
     handleConflictsResponse on the other hand handles where the local copy save was not triumphant on the server.
    Instead the conflict includes the server item. Here we immediately map the server value onto our local value,
    but before that, we give our local value a chance to duplicate itself if it differs from the server value.
    */

  }, {
    key: "handleConflictsResponse",
    value: function () {
      var _ref106 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee96(conflicts) {
        var localValues, _iteratorNormalCompletion46, _didIteratorError46, _iteratorError46, _iterator46, _step46, conflict, serverItemResponse, localItem, frozenContent, itemsNeedingLocalSave, _iteratorNormalCompletion47, _didIteratorError47, _iteratorError47, _iterator47, _step47, _conflict, _localValues$serverIt, itemRef, tempServerItem, _tempItemWithFrozenValues, frozenContentDiffers, currentContentDiffers, duplicateLocal, duplicateServer, keepLocal, keepServer, IsActiveItemSecondsThreshold, isActivelyBeingEdited, contentExcludingReferencesDiffers, isOnlyReferenceChange, localDuplicate;

        return regeneratorRuntime.wrap(function _callee96$(_context96) {
          while (1) {
            switch (_context96.prev = _context96.next) {
              case 0:
                if (!(!conflicts || conflicts.length == 0)) {
                  _context96.next = 2;
                  break;
                }

                return _context96.abrupt("return");

              case 2:

                if (this.loggingEnabled) {
                  console.log("Handle Conflicted Items:", conflicts);
                }

                // Get local values before doing any processing. This way, if a note change below modifies a tag,
                // and the tag is going to be iterated on in the same loop, then we don't want this change to be compared
                // to the local value.
                localValues = {};
                _iteratorNormalCompletion46 = true;
                _didIteratorError46 = false;
                _iteratorError46 = undefined;
                _context96.prev = 7;
                _iterator46 = conflicts[Symbol.iterator]();

              case 9:
                if (_iteratorNormalCompletion46 = (_step46 = _iterator46.next()).done) {
                  _context96.next = 21;
                  break;
                }

                conflict = _step46.value;
                serverItemResponse = conflict.server_item || conflict.unsaved_item;
                localItem = this.modelManager.findItem(serverItemResponse.uuid);

                if (localItem) {
                  _context96.next = 16;
                  break;
                }

                localValues[serverItemResponse.uuid] = {};
                return _context96.abrupt("continue", 18);

              case 16:
                frozenContent = localItem.getContentCopy();

                localValues[serverItemResponse.uuid] = { frozenContent: frozenContent, itemRef: localItem };

              case 18:
                _iteratorNormalCompletion46 = true;
                _context96.next = 9;
                break;

              case 21:
                _context96.next = 27;
                break;

              case 23:
                _context96.prev = 23;
                _context96.t0 = _context96["catch"](7);
                _didIteratorError46 = true;
                _iteratorError46 = _context96.t0;

              case 27:
                _context96.prev = 27;
                _context96.prev = 28;

                if (!_iteratorNormalCompletion46 && _iterator46.return) {
                  _iterator46.return();
                }

              case 30:
                _context96.prev = 30;

                if (!_didIteratorError46) {
                  _context96.next = 33;
                  break;
                }

                throw _iteratorError46;

              case 33:
                return _context96.finish(30);

              case 34:
                return _context96.finish(27);

              case 35:

                // Any item that's newly created here or updated will need to be persisted
                itemsNeedingLocalSave = [];
                _iteratorNormalCompletion47 = true;
                _didIteratorError47 = false;
                _iteratorError47 = undefined;
                _context96.prev = 39;
                _iterator47 = conflicts[Symbol.iterator]();

              case 41:
                if (_iteratorNormalCompletion47 = (_step47 = _iterator47.next()).done) {
                  _context96.next = 84;
                  break;
                }

                _conflict = _step47.value;

                // if sync_conflict, we receive conflict.server_item.
                // If uuid_conflict, we receive the value we attempted to save.
                serverItemResponse = _conflict.server_item || _conflict.unsaved_item;
                _context96.t1 = SFJS.itemTransformer;
                _context96.t2 = [serverItemResponse];
                _context96.next = 48;
                return this.getActiveKeyInfo(SFSyncManager.KeyRequestLoadSaveAccount);

              case 48:
                _context96.t3 = _context96.sent.keys;
                _context96.next = 51;
                return _context96.t1.decryptMultipleItems.call(_context96.t1, _context96.t2, _context96.t3);

              case 51:
                _localValues$serverIt = localValues[serverItemResponse.uuid], frozenContent = _localValues$serverIt.frozenContent, itemRef = _localValues$serverIt.itemRef;

                // Could be deleted

                if (itemRef) {
                  _context96.next = 54;
                  break;
                }

                return _context96.abrupt("continue", 81);

              case 54:
                if (!(_conflict.type === "uuid_conflict")) {
                  _context96.next = 58;
                  break;
                }

                _context96.next = 57;
                return this.modelManager.alternateUUIDForItem(itemRef);

              case 57:
                return _context96.abrupt("continue", 81);

              case 58:
                if (!(_conflict.type !== "sync_conflict")) {
                  _context96.next = 61;
                  break;
                }

                console.error("Unsupported conflict type", _conflict.type);
                return _context96.abrupt("continue", 81);

              case 61:
                _context96.next = 63;
                return this.modelManager.createDuplicateItemFromResponseItem(serverItemResponse);

              case 63:
                tempServerItem = _context96.sent;

                // Convert to an object simply so we can have access to the `isItemContentEqualWith` function.
                _tempItemWithFrozenValues = this.modelManager.duplicateItemWithCustomContent({
                  content: frozenContent, duplicateOf: itemRef
                });

                // if !frozenContentDiffers && currentContentDiffers, it means values have changed as we were looping through conflicts here.

                frozenContentDiffers = !_tempItemWithFrozenValues.isItemContentEqualWith(tempServerItem);
                currentContentDiffers = !itemRef.isItemContentEqualWith(tempServerItem);
                duplicateLocal = false;
                duplicateServer = false;
                keepLocal = false;
                keepServer = false;


                if (serverItemResponse.deleted || itemRef.deleted) {
                  keepServer = true;
                } else if (frozenContentDiffers) {
                  IsActiveItemSecondsThreshold = 20;
                  isActivelyBeingEdited = (new Date() - itemRef.client_updated_at) / 1000 < IsActiveItemSecondsThreshold;

                  if (isActivelyBeingEdited) {
                    keepLocal = true;
                    duplicateServer = true;
                  } else {
                    duplicateLocal = true;
                    keepServer = true;
                  }
                } else if (currentContentDiffers) {
                  contentExcludingReferencesDiffers = !SFItem.AreItemContentsEqual({
                    leftContent: itemRef.content,
                    rightContent: tempServerItem.content,
                    keysToIgnore: itemRef.keysToIgnoreWhenCheckingContentEquality().concat(["references"]),
                    appDataKeysToIgnore: itemRef.appDataKeysToIgnoreWhenCheckingContentEquality()
                  });
                  isOnlyReferenceChange = !contentExcludingReferencesDiffers;

                  if (isOnlyReferenceChange) {
                    keepServer = false;
                    keepLocal = true;
                  } else {
                    duplicateLocal = true;
                    keepServer = true;
                  }
                } else {
                  // items are exactly equal
                  keepServer = true;
                }

                if (!duplicateLocal) {
                  _context96.next = 77;
                  break;
                }

                _context96.next = 75;
                return this.modelManager.duplicateItemWithCustomContentAndAddAsConflict({
                  content: frozenContent, duplicateOf: itemRef
                });

              case 75:
                localDuplicate = _context96.sent;

                itemsNeedingLocalSave.push(localDuplicate);

              case 77:

                if (duplicateServer) {
                  this.modelManager.addDuplicatedItemAsConflict({
                    duplicate: tempServerItem,
                    duplicateOf: itemRef
                  });
                  itemsNeedingLocalSave.push(tempServerItem);
                }

                if (keepServer) {
                  this.modelManager.mapResponseItemsToLocalModelsOmittingFields([serverItemResponse], null, SFModelManager.MappingSourceRemoteRetrieved);
                }

                if (keepLocal) {
                  itemRef.updated_at = tempServerItem.updated_at;
                  itemRef.setDirty(true);
                }

                // Item ref is always added, since it's value will have changed above, either by mapping, being set to dirty,
                // or being set undirty by the caller but the caller not saving because they're waiting on us.
                itemsNeedingLocalSave.push(itemRef);

              case 81:
                _iteratorNormalCompletion47 = true;
                _context96.next = 41;
                break;

              case 84:
                _context96.next = 90;
                break;

              case 86:
                _context96.prev = 86;
                _context96.t4 = _context96["catch"](39);
                _didIteratorError47 = true;
                _iteratorError47 = _context96.t4;

              case 90:
                _context96.prev = 90;
                _context96.prev = 91;

                if (!_iteratorNormalCompletion47 && _iterator47.return) {
                  _iterator47.return();
                }

              case 93:
                _context96.prev = 93;

                if (!_didIteratorError47) {
                  _context96.next = 96;
                  break;
                }

                throw _iteratorError47;

              case 96:
                return _context96.finish(93);

              case 97:
                return _context96.finish(90);

              case 98:
                return _context96.abrupt("return", itemsNeedingLocalSave);

              case 99:
              case "end":
                return _context96.stop();
            }
          }
        }, _callee96, this, [[7, 23, 27, 35], [28,, 30, 34], [39, 86, 90, 98], [91,, 93, 97]]);
      }));

      function handleConflictsResponse(_x123) {
        return _ref106.apply(this, arguments);
      }

      return handleConflictsResponse;
    }()

    // Legacy API

  }, {
    key: "deprecated_handleUnsavedItemsResponse",
    value: function () {
      var _ref107 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee97(unsaved) {
        var _iteratorNormalCompletion48, _didIteratorError48, _iteratorError48, _iterator48, _step48, mapping, itemResponse, item, error, dup;

        return regeneratorRuntime.wrap(function _callee97$(_context97) {
          while (1) {
            switch (_context97.prev = _context97.next) {
              case 0:
                if (!(!unsaved || unsaved.length == 0)) {
                  _context97.next = 2;
                  break;
                }

                return _context97.abrupt("return");

              case 2:

                if (this.loggingEnabled) {
                  console.log("Handle Unsaved Items:", unsaved);
                }

                _iteratorNormalCompletion48 = true;
                _didIteratorError48 = false;
                _iteratorError48 = undefined;
                _context97.prev = 6;
                _iterator48 = unsaved[Symbol.iterator]();

              case 8:
                if (_iteratorNormalCompletion48 = (_step48 = _iterator48.next()).done) {
                  _context97.next = 35;
                  break;
                }

                mapping = _step48.value;
                itemResponse = mapping.item;
                _context97.t0 = SFJS.itemTransformer;
                _context97.t1 = [itemResponse];
                _context97.next = 15;
                return this.getActiveKeyInfo(SFSyncManager.KeyRequestLoadSaveAccount);

              case 15:
                _context97.t2 = _context97.sent.keys;
                _context97.next = 18;
                return _context97.t0.decryptMultipleItems.call(_context97.t0, _context97.t1, _context97.t2);

              case 18:
                item = this.modelManager.findItem(itemResponse.uuid);

                // Could be deleted

                if (item) {
                  _context97.next = 21;
                  break;
                }

                return _context97.abrupt("continue", 32);

              case 21:
                error = mapping.error;

                if (!(error.tag === "uuid_conflict")) {
                  _context97.next = 27;
                  break;
                }

                _context97.next = 25;
                return this.modelManager.alternateUUIDForItem(item);

              case 25:
                _context97.next = 32;
                break;

              case 27:
                if (!(error.tag === "sync_conflict")) {
                  _context97.next = 32;
                  break;
                }

                _context97.next = 30;
                return this.modelManager.createDuplicateItemFromResponseItem(itemResponse);

              case 30:
                dup = _context97.sent;

                if (!itemResponse.deleted && !item.isItemContentEqualWith(dup)) {
                  this.modelManager.addDuplicatedItemAsConflict({ duplicate: dup, duplicateOf: item });
                }

              case 32:
                _iteratorNormalCompletion48 = true;
                _context97.next = 8;
                break;

              case 35:
                _context97.next = 41;
                break;

              case 37:
                _context97.prev = 37;
                _context97.t3 = _context97["catch"](6);
                _didIteratorError48 = true;
                _iteratorError48 = _context97.t3;

              case 41:
                _context97.prev = 41;
                _context97.prev = 42;

                if (!_iteratorNormalCompletion48 && _iterator48.return) {
                  _iterator48.return();
                }

              case 44:
                _context97.prev = 44;

                if (!_didIteratorError48) {
                  _context97.next = 47;
                  break;
                }

                throw _iteratorError48;

              case 47:
                return _context97.finish(44);

              case 48:
                return _context97.finish(41);

              case 49:
              case "end":
                return _context97.stop();
            }
          }
        }, _callee97, this, [[6, 37, 41, 49], [42,, 44, 48]]);
      }));

      function deprecated_handleUnsavedItemsResponse(_x124) {
        return _ref107.apply(this, arguments);
      }

      return deprecated_handleUnsavedItemsResponse;
    }()

    /*
      Executes a sync request with a blank sync token and high download limit. It will download all items,
      but won't do anything with them other than decrypting, creating respective objects, and returning them to caller. (it does not map them nor establish their relationships)
      The use case came primarly for clients who had ignored a certain content_type in sync, but later issued an update
      indicated they actually did want to start handling that content type. In that case, they would need to download all items
      freshly from the server.
    */

  }, {
    key: "stateless_downloadAllItems",
    value: function stateless_downloadAllItems() {
      var _this25 = this;

      var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

      return new Promise(function () {
        var _ref108 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee99(resolve, reject) {
          var params;
          return regeneratorRuntime.wrap(function _callee99$(_context99) {
            while (1) {
              switch (_context99.prev = _context99.next) {
                case 0:
                  params = {
                    limit: options.limit || 500,
                    sync_token: options.syncToken,
                    cursor_token: options.cursorToken,
                    content_type: options.contentType,
                    event: options.event
                  };
                  _context99.prev = 1;
                  _context99.t0 = _this25.httpManager;
                  _context99.next = 5;
                  return _this25.getSyncURL();

                case 5:
                  _context99.t1 = _context99.sent;
                  _context99.t2 = params;

                  _context99.t3 = function () {
                    var _ref109 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee98(response) {
                      var incomingItems, keys;
                      return regeneratorRuntime.wrap(function _callee98$(_context98) {
                        while (1) {
                          switch (_context98.prev = _context98.next) {
                            case 0:
                              if (!options.retrievedItems) {
                                options.retrievedItems = [];
                              }

                              incomingItems = response.retrieved_items;
                              _context98.next = 4;
                              return _this25.getActiveKeyInfo(SFSyncManager.KeyRequestLoadSaveAccount);

                            case 4:
                              keys = _context98.sent.keys;
                              _context98.next = 7;
                              return SFJS.itemTransformer.decryptMultipleItems(incomingItems, keys);

                            case 7:

                              options.retrievedItems = options.retrievedItems.concat(incomingItems.map(function (incomingItem) {
                                // Create model classes
                                return _this25.modelManager.createItem(incomingItem);
                              }));
                              options.syncToken = response.sync_token;
                              options.cursorToken = response.cursor_token;

                              if (options.cursorToken) {
                                _this25.stateless_downloadAllItems(options).then(resolve);
                              } else {
                                resolve(options.retrievedItems);
                              }

                            case 11:
                            case "end":
                              return _context98.stop();
                          }
                        }
                      }, _callee98, _this25);
                    }));

                    return function (_x128) {
                      return _ref109.apply(this, arguments);
                    };
                  }();

                  _context99.t4 = function (response, statusCode) {
                    reject(response);
                  };

                  _context99.t0.postAbsolute.call(_context99.t0, _context99.t1, _context99.t2, _context99.t3, _context99.t4);

                  _context99.next = 16;
                  break;

                case 12:
                  _context99.prev = 12;
                  _context99.t5 = _context99["catch"](1);

                  console.log("Download all items exception caught:", _context99.t5);
                  reject(_context99.t5);

                case 16:
                case "end":
                  return _context99.stop();
              }
            }
          }, _callee99, _this25, [[1, 12]]);
        }));

        return function (_x126, _x127) {
          return _ref108.apply(this, arguments);
        };
      }());
    }
  }, {
    key: "resolveOutOfSync",
    value: function () {
      var _ref110 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee101() {
        var _this26 = this;

        return regeneratorRuntime.wrap(function _callee101$(_context101) {
          while (1) {
            switch (_context101.prev = _context101.next) {
              case 0:
                return _context101.abrupt("return", this.stateless_downloadAllItems({ event: "resolve-out-of-sync" }).then(function () {
                  var _ref111 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee100(downloadedItems) {
                    var itemsToMap, _iteratorNormalCompletion49, _didIteratorError49, _iteratorError49, _iterator49, _step49, downloadedItem, existingItem, contentDoesntMatch;

                    return regeneratorRuntime.wrap(function _callee100$(_context100) {
                      while (1) {
                        switch (_context100.prev = _context100.next) {
                          case 0:
                            itemsToMap = [];
                            _iteratorNormalCompletion49 = true;
                            _didIteratorError49 = false;
                            _iteratorError49 = undefined;
                            _context100.prev = 4;
                            _iterator49 = downloadedItems[Symbol.iterator]();

                          case 6:
                            if (_iteratorNormalCompletion49 = (_step49 = _iterator49.next()).done) {
                              _context100.next = 18;
                              break;
                            }

                            downloadedItem = _step49.value;

                            // Note that deleted items will not be sent back by the server.
                            existingItem = _this26.modelManager.findItem(downloadedItem.uuid);

                            if (!existingItem) {
                              _context100.next = 14;
                              break;
                            }

                            // Check if the content differs. If it does, create a new item, and do not map downloadedItem.
                            contentDoesntMatch = !downloadedItem.isItemContentEqualWith(existingItem);

                            if (!contentDoesntMatch) {
                              _context100.next = 14;
                              break;
                            }

                            _context100.next = 14;
                            return _this26.modelManager.duplicateItemAndAddAsConflict(existingItem);

                          case 14:

                            // Map the downloadedItem as authoritive content. If client copy at all differed, we would have created a duplicate of it above and synced it.
                            // This is also neccessary to map the updated_at value from the server
                            itemsToMap.push(downloadedItem);

                          case 15:
                            _iteratorNormalCompletion49 = true;
                            _context100.next = 6;
                            break;

                          case 18:
                            _context100.next = 24;
                            break;

                          case 20:
                            _context100.prev = 20;
                            _context100.t0 = _context100["catch"](4);
                            _didIteratorError49 = true;
                            _iteratorError49 = _context100.t0;

                          case 24:
                            _context100.prev = 24;
                            _context100.prev = 25;

                            if (!_iteratorNormalCompletion49 && _iterator49.return) {
                              _iterator49.return();
                            }

                          case 27:
                            _context100.prev = 27;

                            if (!_didIteratorError49) {
                              _context100.next = 30;
                              break;
                            }

                            throw _iteratorError49;

                          case 30:
                            return _context100.finish(27);

                          case 31:
                            return _context100.finish(24);

                          case 32:

                            _this26.modelManager.mapResponseItemsToLocalModelsWithOptions({ items: itemsToMap, source: SFModelManager.MappingSourceRemoteRetrieved });
                            // Save all items locally. Usually sync() would save downloaded items locally, but we're using stateless_sync here, so we have to do it manually
                            _context100.next = 35;
                            return _this26.writeItemsToLocalStorage(_this26.modelManager.allNondummyItems);

                          case 35:
                            return _context100.abrupt("return", _this26.sync({ performIntegrityCheck: true }));

                          case 36:
                          case "end":
                            return _context100.stop();
                        }
                      }
                    }, _callee100, _this26, [[4, 20, 24, 32], [25,, 27, 31]]);
                  }));

                  return function (_x129) {
                    return _ref111.apply(this, arguments);
                  };
                }()));

              case 1:
              case "end":
                return _context101.stop();
            }
          }
        }, _callee101, this);
      }));

      function resolveOutOfSync() {
        return _ref110.apply(this, arguments);
      }

      return resolveOutOfSync;
    }()
  }, {
    key: "handleSignout",
    value: function () {
      var _ref112 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee102() {
        return regeneratorRuntime.wrap(function _callee102$(_context102) {
          while (1) {
            switch (_context102.prev = _context102.next) {
              case 0:
                this.loadLocalDataPromise = null;
                this.performSyncAgainOnCompletion = false;
                this.syncStatus.syncOpInProgress = false;
                this._queuedCallbacks = [];
                this.syncStatus = {};
                return _context102.abrupt("return", this.clearSyncToken());

              case 6:
              case "end":
                return _context102.stop();
            }
          }
        }, _callee102, this);
      }));

      function handleSignout() {
        return _ref112.apply(this, arguments);
      }

      return handleSignout;
    }()
  }, {
    key: "clearSyncToken",
    value: function () {
      var _ref113 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee103() {
        return regeneratorRuntime.wrap(function _callee103$(_context103) {
          while (1) {
            switch (_context103.prev = _context103.next) {
              case 0:
                this._syncToken = null;
                this._cursorToken = null;
                return _context103.abrupt("return", this.storageManager.removeItem("syncToken"));

              case 3:
              case "end":
                return _context103.stop();
            }
          }
        }, _callee103, this);
      }));

      function clearSyncToken() {
        return _ref113.apply(this, arguments);
      }

      return clearSyncToken;
    }()
  }, {
    key: "__setLocalDataNotLoaded",
    value: function __setLocalDataNotLoaded() {
      this._initialDataLoaded = false;
    }
  }, {
    key: "queuedCallbacks",
    get: function get() {
      if (!this._queuedCallbacks) {
        this._queuedCallbacks = [];
      }
      return this._queuedCallbacks;
    }
  }]);

  return SFSyncManager;
}();

;var dateFormatter;

var SFItem = exports.SFItem = function () {
  function SFItem() {
    var json_obj = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, SFItem);

    this.content = {};
    this.referencingObjects = [];
    this.updateFromJSON(json_obj);

    if (!this.uuid) {
      // on React Native, this method will not exist. UUID gen will be handled manually via async methods.
      if (typeof SFJS !== "undefined" && SFJS.crypto.generateUUIDSync) {
        this.uuid = SFJS.crypto.generateUUIDSync();
      }
    }

    if (_typeof(this.content) === 'object' && !this.content.references) {
      this.content.references = [];
    }
  }

  // On some platforms, syncrounous uuid generation is not available.
  // Those platforms (mobile) must call this function manually.


  _createClass(SFItem, [{
    key: "initUUID",
    value: function () {
      var _ref114 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee104() {
        return regeneratorRuntime.wrap(function _callee104$(_context104) {
          while (1) {
            switch (_context104.prev = _context104.next) {
              case 0:
                if (this.uuid) {
                  _context104.next = 4;
                  break;
                }

                _context104.next = 3;
                return SFJS.crypto.generateUUID();

              case 3:
                this.uuid = _context104.sent;

              case 4:
              case "end":
                return _context104.stop();
            }
          }
        }, _callee104, this);
      }));

      function initUUID() {
        return _ref114.apply(this, arguments);
      }

      return initUUID;
    }()
  }, {
    key: "updateFromJSON",
    value: function updateFromJSON(json) {
      // Don't expect this to ever be the case but we're having a crash with Android and this is the only suspect.
      if (!json) {
        return;
      }

      this.deleted = json.deleted;
      this.uuid = json.uuid;
      this.enc_item_key = json.enc_item_key;
      this.auth_hash = json.auth_hash;
      this.auth_params = json.auth_params;

      // When updating from server response (as opposed to local json response), these keys will be missing.
      // So we only want to update these values if they are explicitly present.
      var clientKeys = ["errorDecrypting", "dirty", "dirtyCount", "dirtiedDate", "dummy"];
      var _iteratorNormalCompletion50 = true;
      var _didIteratorError50 = false;
      var _iteratorError50 = undefined;

      try {
        for (var _iterator50 = clientKeys[Symbol.iterator](), _step50; !(_iteratorNormalCompletion50 = (_step50 = _iterator50.next()).done); _iteratorNormalCompletion50 = true) {
          var key = _step50.value;

          if (json[key] !== undefined) {
            this[key] = json[key];
          }
        }
      } catch (err) {
        _didIteratorError50 = true;
        _iteratorError50 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion50 && _iterator50.return) {
            _iterator50.return();
          }
        } finally {
          if (_didIteratorError50) {
            throw _iteratorError50;
          }
        }
      }

      if (this.dirtiedDate && typeof this.dirtiedDate === 'string') {
        this.dirtiedDate = new Date(this.dirtiedDate);
      }

      // Check if object has getter for content_type, and if so, skip
      if (!this.content_type) {
        this.content_type = json.content_type;
      }

      // this.content = json.content will copy it by reference rather than value. So we need to do a deep merge after.
      // json.content can still be a string here. We copy it to this.content, then do a deep merge to transfer over all values.

      if (json.errorDecrypting) {
        this.content = json.content;
      } else {
        try {
          var parsedContent = typeof json.content === 'string' ? JSON.parse(json.content) : json.content;
          SFItem.deepMerge(this.contentObject, parsedContent);
        } catch (e) {
          console.log("Error while updating item from json", e);
        }
      }

      // Manually merge top level data instead of wholesale merge
      if (json.created_at) {
        this.created_at = json.created_at;
      }
      // Could be null if we're mapping from an extension bridge, where we remove this as its a private property.
      if (json.updated_at) {
        this.updated_at = json.updated_at;
      }

      if (this.created_at) {
        this.created_at = new Date(this.created_at);
        this.updated_at = new Date(this.updated_at);
      } else {
        this.created_at = new Date();
        this.updated_at = new Date(0); // epoch
      }

      // Allows the getter to be re-invoked
      this._client_updated_at = null;

      if (json.content) {
        this.mapContentToLocalProperties(this.contentObject);
      } else if (json.deleted == true) {
        this.handleDeletedContent();
      }
    }
  }, {
    key: "mapContentToLocalProperties",
    value: function mapContentToLocalProperties(contentObj) {}
  }, {
    key: "createContentJSONFromProperties",
    value: function createContentJSONFromProperties() {
      /*
      NOTE: This function does have side effects and WILL modify our content.
       Subclasses will override structureParams, and add their own custom content and properties to the object returned from structureParams
      These are properties that this superclass will not be aware of, like 'title' or 'text'
       When we call createContentJSONFromProperties, we want to update our own inherit 'content' field with the values returned from structureParams,
      so that our content field is up to date.
       Each subclass will call super.structureParams and merge it with its own custom result object.
      Since our own structureParams gets a real-time copy of our content, it should be safe to merge the aggregate value back into our own content field.
      */
      var content = this.structureParams();

      SFItem.deepMerge(this.contentObject, content);

      // Return the content item copy and not our actual value, as we don't want it to be mutated outside our control.
      return content;
    }
  }, {
    key: "structureParams",
    value: function structureParams() {
      return this.getContentCopy();
    }

    /* Allows the item to handle the case where the item is deleted and the content is null */

  }, {
    key: "handleDeletedContent",
    value: function handleDeletedContent() {
      // Subclasses can override
    }
  }, {
    key: "setDirty",
    value: function setDirty(dirty, updateClientDate) {
      this.dirty = dirty;

      // Allows the syncManager to check if an item has been marked dirty after a sync has been started
      // This prevents it from clearing it as a dirty item after sync completion, if someone else has marked it dirty
      // again after an ongoing sync.
      if (!this.dirtyCount) {
        this.dirtyCount = 0;
      }
      if (dirty) {
        this.dirtyCount++;
      } else {
        this.dirtyCount = 0;
      }

      // Used internally by syncManager to determine if a dirted item needs to be saved offline.
      // You want to set this in both cases, when dirty is true and false. If it's false, we still need
      // to save it to disk as an update.
      this.dirtiedDate = new Date();

      if (dirty && updateClientDate) {
        // Set the client modified date to now if marking the item as dirty
        this.client_updated_at = new Date();
      } else if (!this.hasRawClientUpdatedAtValue()) {
        // if we don't have an explcit raw value, we initialize client_updated_at.
        this.client_updated_at = new Date(this.updated_at);
      }
    }
  }, {
    key: "updateLocalRelationships",
    value: function updateLocalRelationships() {
      // optional override
    }
  }, {
    key: "addItemAsRelationship",
    value: function addItemAsRelationship(item) {
      item.setIsBeingReferencedBy(this);

      if (this.hasRelationshipWithItem(item)) {
        return;
      }

      var references = this.content.references || [];
      references.push({
        uuid: item.uuid,
        content_type: item.content_type
      });
      this.content.references = references;
    }
  }, {
    key: "removeItemAsRelationship",
    value: function removeItemAsRelationship(item) {
      item.setIsNoLongerBeingReferencedBy(this);
      this.removeReferenceWithUuid(item.uuid);
    }

    // When another object has a relationship with us, we push that object into memory here.
    // We use this so that when `this` is deleted, we're able to update the references of those other objects.

  }, {
    key: "setIsBeingReferencedBy",
    value: function setIsBeingReferencedBy(item) {
      if (!_.find(this.referencingObjects, { uuid: item.uuid })) {
        this.referencingObjects.push(item);
      }
    }
  }, {
    key: "setIsNoLongerBeingReferencedBy",
    value: function setIsNoLongerBeingReferencedBy(item) {
      _.remove(this.referencingObjects, { uuid: item.uuid });
      // Legacy two-way relationships should be handled here
      if (this.hasRelationshipWithItem(item)) {
        this.removeReferenceWithUuid(item.uuid);
        // We really shouldn't have the authority to set this item as dirty, but it's the only way to save this change.
        this.setDirty(true);
      }
    }
  }, {
    key: "removeReferenceWithUuid",
    value: function removeReferenceWithUuid(uuid) {
      var references = this.content.references || [];
      references = references.filter(function (r) {
        return r.uuid != uuid;
      });
      this.content.references = references;
    }
  }, {
    key: "hasRelationshipWithItem",
    value: function hasRelationshipWithItem(item) {
      var target = this.content.references.find(function (r) {
        return r.uuid == item.uuid;
      });
      return target != null;
    }
  }, {
    key: "isBeingRemovedLocally",
    value: function isBeingRemovedLocally() {}
  }, {
    key: "didFinishSyncing",
    value: function didFinishSyncing() {}
  }, {
    key: "informReferencesOfUUIDChange",
    value: function informReferencesOfUUIDChange(oldUUID, newUUID) {
      // optional override
    }
  }, {
    key: "potentialItemOfInterestHasChangedItsUUID",
    value: function potentialItemOfInterestHasChangedItsUUID(newItem, oldUUID, newUUID) {
      // optional override
      var _iteratorNormalCompletion51 = true;
      var _didIteratorError51 = false;
      var _iteratorError51 = undefined;

      try {
        for (var _iterator51 = this.content.references[Symbol.iterator](), _step51; !(_iteratorNormalCompletion51 = (_step51 = _iterator51.next()).done); _iteratorNormalCompletion51 = true) {
          var reference = _step51.value;

          if (reference.uuid == oldUUID) {
            reference.uuid = newUUID;
            this.setDirty(true);
          }
        }
      } catch (err) {
        _didIteratorError51 = true;
        _iteratorError51 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion51 && _iterator51.return) {
            _iterator51.return();
          }
        } finally {
          if (_didIteratorError51) {
            throw _iteratorError51;
          }
        }
      }
    }
  }, {
    key: "doNotEncrypt",
    value: function doNotEncrypt() {
      return false;
    }

    /*
    App Data
    */

  }, {
    key: "setDomainDataItem",
    value: function setDomainDataItem(key, value, domain) {
      if (!domain) {
        console.error("SFItem.AppDomain needs to be set.");
        return;
      }

      if (this.errorDecrypting) {
        return;
      }

      if (!this.content.appData) {
        this.content.appData = {};
      }

      var data = this.content.appData[domain];
      if (!data) {
        data = {};
      }
      data[key] = value;
      this.content.appData[domain] = data;
    }
  }, {
    key: "getDomainDataItem",
    value: function getDomainDataItem(key, domain) {
      if (!domain) {
        console.error("SFItem.AppDomain needs to be set.");
        return;
      }

      if (this.errorDecrypting) {
        return;
      }

      if (!this.content.appData) {
        this.content.appData = {};
      }

      var data = this.content.appData[domain];
      if (data) {
        return data[key];
      } else {
        return null;
      }
    }
  }, {
    key: "setAppDataItem",
    value: function setAppDataItem(key, value) {
      this.setDomainDataItem(key, value, SFItem.AppDomain);
    }
  }, {
    key: "getAppDataItem",
    value: function getAppDataItem(key) {
      return this.getDomainDataItem(key, SFItem.AppDomain);
    }
  }, {
    key: "hasRawClientUpdatedAtValue",
    value: function hasRawClientUpdatedAtValue() {
      return this.getAppDataItem("client_updated_at") != null;
    }
  }, {
    key: "keysToIgnoreWhenCheckingContentEquality",


    /*
      During sync conflicts, when determing whether to create a duplicate for an item, we can omit keys that have no
      meaningful weight and can be ignored. For example, if one component has active = true and another component has active = false,
      it would be silly to duplicate them, so instead we ignore this.
     */
    value: function keysToIgnoreWhenCheckingContentEquality() {
      return [];
    }

    // Same as above, but keys inside appData[Item.AppDomain]

  }, {
    key: "appDataKeysToIgnoreWhenCheckingContentEquality",
    value: function appDataKeysToIgnoreWhenCheckingContentEquality() {
      return ["client_updated_at"];
    }
  }, {
    key: "getContentCopy",
    value: function getContentCopy() {
      var contentCopy = JSON.parse(JSON.stringify(this.content));
      return contentCopy;
    }
  }, {
    key: "isItemContentEqualWith",
    value: function isItemContentEqualWith(otherItem) {
      return SFItem.AreItemContentsEqual({
        leftContent: this.content,
        rightContent: otherItem.content,
        keysToIgnore: this.keysToIgnoreWhenCheckingContentEquality(),
        appDataKeysToIgnore: this.appDataKeysToIgnoreWhenCheckingContentEquality()
      });
    }
  }, {
    key: "satisfiesPredicate",
    value: function satisfiesPredicate(predicate) {
      /*
      Predicate is an SFPredicate having properties:
      {
        keypath: String,
        operator: String,
        value: object
      }
       */
      return SFPredicate.ItemSatisfiesPredicate(this, predicate);
    }

    /*
    Dates
    */

  }, {
    key: "createdAtString",
    value: function createdAtString() {
      return this.dateToLocalizedString(this.created_at);
    }
  }, {
    key: "updatedAtString",
    value: function updatedAtString() {
      return this.dateToLocalizedString(this.client_updated_at);
    }
  }, {
    key: "updatedAtTimestamp",
    value: function updatedAtTimestamp() {
      return this.updated_at.getTime();
    }
  }, {
    key: "dateToLocalizedString",
    value: function dateToLocalizedString(date) {
      if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {
        if (!dateFormatter) {
          var locale = navigator.languages && navigator.languages.length ? navigator.languages[0] : navigator.language;
          dateFormatter = new Intl.DateTimeFormat(locale, {
            year: 'numeric',
            month: 'short',
            day: '2-digit',
            weekday: 'long',
            hour: '2-digit',
            minute: '2-digit'
          });
        }
        return dateFormatter.format(date);
      } else {
        // IE < 11, Safari <= 9.0.
        // In English, this generates the string most similar to
        // the toLocaleDateString() result above.
        return date.toDateString() + ' ' + date.toLocaleTimeString();
      }
    }
  }, {
    key: "contentObject",
    get: function get() {

      if (this.errorDecrypting) {
        return this.content;
      }

      if (!this.content) {
        this.content = {};
        return this.content;
      }

      if (this.content !== null && _typeof(this.content) === 'object') {
        // this is the case when mapping localStorage content, in which case the content is already parsed
        return this.content;
      }

      try {
        var content = JSON.parse(this.content);
        this.content = content;
        return this.content;
      } catch (e) {
        console.log("Error parsing json", e, this);
        this.content = {};
        return this.content;
      }
    }
  }, {
    key: "pinned",
    get: function get() {
      return this.getAppDataItem("pinned");
    }
  }, {
    key: "archived",
    get: function get() {
      return this.getAppDataItem("archived");
    }
  }, {
    key: "locked",
    get: function get() {
      return this.getAppDataItem("locked");
    }

    // May be used by clients to display the human readable type for this item. Should be overriden by subclasses.

  }, {
    key: "displayName",
    get: function get() {
      return "Item";
    }
  }, {
    key: "client_updated_at",
    get: function get() {
      if (!this._client_updated_at) {
        var saved = this.getAppDataItem("client_updated_at");
        if (saved) {
          this._client_updated_at = new Date(saved);
        } else {
          this._client_updated_at = new Date(this.updated_at);
        }
      }
      return this._client_updated_at;
    },
    set: function set(date) {
      this._client_updated_at = date;

      this.setAppDataItem("client_updated_at", date);
    }
  }], [{
    key: "deepMerge",
    value: function deepMerge(a, b) {
      // By default _.merge will not merge a full array with an empty one.
      // We want to replace arrays wholesale
      function mergeCopyArrays(objValue, srcValue) {
        if (_.isArray(objValue)) {
          return srcValue;
        }
      }
      _.mergeWith(a, b, mergeCopyArrays);
      return a;
    }
  }, {
    key: "AreItemContentsEqual",
    value: function AreItemContentsEqual(_ref115) {
      var leftContent = _ref115.leftContent,
          rightContent = _ref115.rightContent,
          keysToIgnore = _ref115.keysToIgnore,
          appDataKeysToIgnore = _ref115.appDataKeysToIgnore;

      var omit = function omit(obj, keys) {
        if (!obj) {
          return obj;
        }
        var _iteratorNormalCompletion52 = true;
        var _didIteratorError52 = false;
        var _iteratorError52 = undefined;

        try {
          for (var _iterator52 = keys[Symbol.iterator](), _step52; !(_iteratorNormalCompletion52 = (_step52 = _iterator52.next()).done); _iteratorNormalCompletion52 = true) {
            var key = _step52.value;

            delete obj[key];
          }
        } catch (err) {
          _didIteratorError52 = true;
          _iteratorError52 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion52 && _iterator52.return) {
              _iterator52.return();
            }
          } finally {
            if (_didIteratorError52) {
              throw _iteratorError52;
            }
          }
        }

        return obj;
      };

      // Create copies of objects before running omit as not to modify source values directly.
      leftContent = JSON.parse(JSON.stringify(leftContent));
      if (leftContent.appData) {
        omit(leftContent.appData[SFItem.AppDomain], appDataKeysToIgnore);
      }
      leftContent = omit(leftContent, keysToIgnore);

      rightContent = JSON.parse(JSON.stringify(rightContent));
      if (rightContent.appData) {
        omit(rightContent.appData[SFItem.AppDomain], appDataKeysToIgnore);
      }
      rightContent = omit(rightContent, keysToIgnore);

      return JSON.stringify(leftContent) === JSON.stringify(rightContent);
    }
  }]);

  return SFItem;
}();

;
var SFItemParams = exports.SFItemParams = function () {
  function SFItemParams(item, keys, auth_params) {
    _classCallCheck(this, SFItemParams);

    this.item = item;
    this.keys = keys;
    this.auth_params = auth_params;

    if (this.keys && !this.auth_params) {
      throw "SFItemParams.auth_params must be supplied if supplying keys.";
    }

    if (this.auth_params && !this.auth_params.version) {
      throw "SFItemParams.auth_params is missing version";
    }
  }

  _createClass(SFItemParams, [{
    key: "paramsForExportFile",
    value: function () {
      var _ref116 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee105(includeDeleted) {
        var result;
        return regeneratorRuntime.wrap(function _callee105$(_context105) {
          while (1) {
            switch (_context105.prev = _context105.next) {
              case 0:
                this.additionalFields = ["updated_at"];
                this.forExportFile = true;

                if (!includeDeleted) {
                  _context105.next = 6;
                  break;
                }

                return _context105.abrupt("return", this.__params());

              case 6:
                _context105.next = 8;
                return this.__params();

              case 8:
                result = _context105.sent;
                return _context105.abrupt("return", _.omit(result, ["deleted"]));

              case 10:
              case "end":
                return _context105.stop();
            }
          }
        }, _callee105, this);
      }));

      function paramsForExportFile(_x131) {
        return _ref116.apply(this, arguments);
      }

      return paramsForExportFile;
    }()
  }, {
    key: "paramsForExtension",
    value: function () {
      var _ref117 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee106() {
        return regeneratorRuntime.wrap(function _callee106$(_context106) {
          while (1) {
            switch (_context106.prev = _context106.next) {
              case 0:
                return _context106.abrupt("return", this.paramsForExportFile());

              case 1:
              case "end":
                return _context106.stop();
            }
          }
        }, _callee106, this);
      }));

      function paramsForExtension() {
        return _ref117.apply(this, arguments);
      }

      return paramsForExtension;
    }()
  }, {
    key: "paramsForLocalStorage",
    value: function () {
      var _ref118 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee107() {
        return regeneratorRuntime.wrap(function _callee107$(_context107) {
          while (1) {
            switch (_context107.prev = _context107.next) {
              case 0:
                this.additionalFields = ["dirty", "dirtiedDate", "errorDecrypting"];
                this.forExportFile = true;
                return _context107.abrupt("return", this.__params());

              case 3:
              case "end":
                return _context107.stop();
            }
          }
        }, _callee107, this);
      }));

      function paramsForLocalStorage() {
        return _ref118.apply(this, arguments);
      }

      return paramsForLocalStorage;
    }()
  }, {
    key: "paramsForSync",
    value: function () {
      var _ref119 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee108() {
        return regeneratorRuntime.wrap(function _callee108$(_context108) {
          while (1) {
            switch (_context108.prev = _context108.next) {
              case 0:
                return _context108.abrupt("return", this.__params());

              case 1:
              case "end":
                return _context108.stop();
            }
          }
        }, _callee108, this);
      }));

      function paramsForSync() {
        return _ref119.apply(this, arguments);
      }

      return paramsForSync;
    }()
  }, {
    key: "__params",
    value: function () {
      var _ref120 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee109() {
        var params, doNotEncrypt, encryptedParams;
        return regeneratorRuntime.wrap(function _callee109$(_context109) {
          while (1) {
            switch (_context109.prev = _context109.next) {
              case 0:
                params = { uuid: this.item.uuid, content_type: this.item.content_type, deleted: this.item.deleted, created_at: this.item.created_at, updated_at: this.item.updated_at };

                if (this.item.errorDecrypting) {
                  _context109.next = 23;
                  break;
                }

                // Items should always be encrypted for export files. Only respect item.doNotEncrypt for remote sync params.
                doNotEncrypt = this.item.doNotEncrypt() && !this.forExportFile;

                if (!(this.keys && !doNotEncrypt)) {
                  _context109.next = 11;
                  break;
                }

                _context109.next = 6;
                return SFJS.itemTransformer.encryptItem(this.item, this.keys, this.auth_params);

              case 6:
                encryptedParams = _context109.sent;

                _.merge(params, encryptedParams);

                if (this.auth_params.version !== "001") {
                  params.auth_hash = null;
                }
                _context109.next = 21;
                break;

              case 11:
                if (!this.forExportFile) {
                  _context109.next = 15;
                  break;
                }

                _context109.t0 = this.item.createContentJSONFromProperties();
                _context109.next = 19;
                break;

              case 15:
                _context109.next = 17;
                return SFJS.crypto.base64(JSON.stringify(this.item.createContentJSONFromProperties()));

              case 17:
                _context109.t1 = _context109.sent;
                _context109.t0 = "000" + _context109.t1;

              case 19:
                params.content = _context109.t0;

                if (!this.forExportFile) {
                  params.enc_item_key = null;
                  params.auth_hash = null;
                }

              case 21:
                _context109.next = 26;
                break;

              case 23:
                // Error decrypting, keep "content" and related fields as is (and do not try to encrypt, otherwise that would be undefined behavior)
                params.content = this.item.content;
                params.enc_item_key = this.item.enc_item_key;
                params.auth_hash = this.item.auth_hash;

              case 26:

                if (this.additionalFields) {
                  _.merge(params, _.pick(this.item, this.additionalFields));
                }

                return _context109.abrupt("return", params);

              case 28:
              case "end":
                return _context109.stop();
            }
          }
        }, _callee109, this);
      }));

      function __params() {
        return _ref120.apply(this, arguments);
      }

      return __params;
    }()
  }]);

  return SFItemParams;
}();

;
var SFPredicate = exports.SFPredicate = function () {
  function SFPredicate(keypath, operator, value) {
    _classCallCheck(this, SFPredicate);

    this.keypath = keypath;
    this.operator = operator;
    this.value = value;

    // Preprocessing to make predicate evaluation faster.
    // Won't recurse forever, but with arbitrarily large input could get stuck. Hope there are input size limits
    // somewhere else.
    if (SFPredicate.IsRecursiveOperator(this.operator)) {
      this.value = this.value.map(SFPredicate.fromArray);
    }
  }

  _createClass(SFPredicate, null, [{
    key: "fromArray",
    value: function fromArray(array) {
      return new SFPredicate(array[0], array[1], array[2]);
    }
  }, {
    key: "ObjectSatisfiesPredicate",
    value: function ObjectSatisfiesPredicate(object, predicate) {
      // Predicates may not always be created using the official constructor
      // so if it's still an array here, convert to object
      if (Array.isArray(predicate)) {
        predicate = this.fromArray(predicate);
      }

      if (SFPredicate.IsRecursiveOperator(predicate.operator)) {
        if (predicate.operator === "and") {
          var _iteratorNormalCompletion53 = true;
          var _didIteratorError53 = false;
          var _iteratorError53 = undefined;

          try {
            for (var _iterator53 = predicate.value[Symbol.iterator](), _step53; !(_iteratorNormalCompletion53 = (_step53 = _iterator53.next()).done); _iteratorNormalCompletion53 = true) {
              var subPredicate = _step53.value;

              if (!this.ObjectSatisfiesPredicate(object, subPredicate)) {
                return false;
              }
            }
          } catch (err) {
            _didIteratorError53 = true;
            _iteratorError53 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion53 && _iterator53.return) {
                _iterator53.return();
              }
            } finally {
              if (_didIteratorError53) {
                throw _iteratorError53;
              }
            }
          }

          return true;
        }
        if (predicate.operator === "or") {
          var _iteratorNormalCompletion54 = true;
          var _didIteratorError54 = false;
          var _iteratorError54 = undefined;

          try {
            for (var _iterator54 = predicate.value[Symbol.iterator](), _step54; !(_iteratorNormalCompletion54 = (_step54 = _iterator54.next()).done); _iteratorNormalCompletion54 = true) {
              var subPredicate = _step54.value;

              if (this.ObjectSatisfiesPredicate(object, subPredicate)) {
                return true;
              }
            }
          } catch (err) {
            _didIteratorError54 = true;
            _iteratorError54 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion54 && _iterator54.return) {
                _iterator54.return();
              }
            } finally {
              if (_didIteratorError54) {
                throw _iteratorError54;
              }
            }
          }

          return false;
        }
      }

      var predicateValue = predicate.value;
      if (typeof predicateValue == 'string' && predicateValue.includes(".ago")) {
        predicateValue = this.DateFromString(predicateValue);
      }

      var valueAtKeyPath = predicate.keypath.split('.').reduce(function (previous, current) {
        return previous && previous[current];
      }, object);

      var falseyValues = [false, "", null, undefined, NaN];

      // If the value at keyPath is undefined, either because the property is nonexistent or the value is null.
      if (valueAtKeyPath == undefined) {
        if (predicate.operator == "!=") {
          return !falseyValues.includes(predicate.value);
        } else {
          return falseyValues.includes(predicate.value);
        }
      }

      if (predicate.operator == "=") {
        // Use array comparison
        if (Array.isArray(valueAtKeyPath)) {
          return JSON.stringify(valueAtKeyPath) == JSON.stringify(predicateValue);
        } else {
          return valueAtKeyPath == predicateValue;
        }
      } else if (predicate.operator == "!=") {
        // Use array comparison
        if (Array.isArray(valueAtKeyPath)) {
          return JSON.stringify(valueAtKeyPath) != JSON.stringify(predicateValue);
        } else {
          return valueAtKeyPath !== predicateValue;
        }
      } else if (predicate.operator == "<") {
        return valueAtKeyPath < predicateValue;
      } else if (predicate.operator == ">") {
        return valueAtKeyPath > predicateValue;
      } else if (predicate.operator == "<=") {
        return valueAtKeyPath <= predicateValue;
      } else if (predicate.operator == ">=") {
        return valueAtKeyPath >= predicateValue;
      } else if (predicate.operator == "startsWith") {
        return valueAtKeyPath.startsWith(predicateValue);
      } else if (predicate.operator == "in") {
        return predicateValue.indexOf(valueAtKeyPath) != -1;
      } else if (predicate.operator == "includes") {
        return this.resolveIncludesPredicate(valueAtKeyPath, predicateValue);
      } else if (predicate.operator == "matches") {
        var regex = new RegExp(predicateValue);
        return regex.test(valueAtKeyPath);
      }

      return false;
    }
  }, {
    key: "resolveIncludesPredicate",
    value: function resolveIncludesPredicate(valueAtKeyPath, predicateValue) {
      // includes can be a string  or a predicate (in array form)
      if (typeof predicateValue == 'string') {
        // if string, simply check if the valueAtKeyPath includes the predicate value
        return valueAtKeyPath.includes(predicateValue);
      } else {
        // is a predicate array or predicate object
        var innerPredicate;
        if (Array.isArray(predicateValue)) {
          innerPredicate = SFPredicate.fromArray(predicateValue);
        } else {
          innerPredicate = predicateValue;
        }
        var _iteratorNormalCompletion55 = true;
        var _didIteratorError55 = false;
        var _iteratorError55 = undefined;

        try {
          for (var _iterator55 = valueAtKeyPath[Symbol.iterator](), _step55; !(_iteratorNormalCompletion55 = (_step55 = _iterator55.next()).done); _iteratorNormalCompletion55 = true) {
            var obj = _step55.value;

            if (this.ObjectSatisfiesPredicate(obj, innerPredicate)) {
              return true;
            }
          }
        } catch (err) {
          _didIteratorError55 = true;
          _iteratorError55 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion55 && _iterator55.return) {
              _iterator55.return();
            }
          } finally {
            if (_didIteratorError55) {
              throw _iteratorError55;
            }
          }
        }

        return false;
      }
    }
  }, {
    key: "ItemSatisfiesPredicate",
    value: function ItemSatisfiesPredicate(item, predicate) {
      if (Array.isArray(predicate)) {
        predicate = SFPredicate.fromArray(predicate);
      }
      return this.ObjectSatisfiesPredicate(item, predicate);
    }
  }, {
    key: "ItemSatisfiesPredicates",
    value: function ItemSatisfiesPredicates(item, predicates) {
      var _iteratorNormalCompletion56 = true;
      var _didIteratorError56 = false;
      var _iteratorError56 = undefined;

      try {
        for (var _iterator56 = predicates[Symbol.iterator](), _step56; !(_iteratorNormalCompletion56 = (_step56 = _iterator56.next()).done); _iteratorNormalCompletion56 = true) {
          var predicate = _step56.value;

          if (!this.ItemSatisfiesPredicate(item, predicate)) {
            return false;
          }
        }
      } catch (err) {
        _didIteratorError56 = true;
        _iteratorError56 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion56 && _iterator56.return) {
            _iterator56.return();
          }
        } finally {
          if (_didIteratorError56) {
            throw _iteratorError56;
          }
        }
      }

      return true;
    }
  }, {
    key: "DateFromString",
    value: function DateFromString(string) {
      // x.days.ago, x.hours.ago
      var comps = string.split(".");
      var unit = comps[1];
      var date = new Date();
      var offset = parseInt(comps[0]);
      if (unit == "days") {
        date.setDate(date.getDate() - offset);
      } else if (unit == "hours") {
        date.setHours(date.getHours() - offset);
      }
      return date;
    }
  }, {
    key: "IsRecursiveOperator",
    value: function IsRecursiveOperator(operator) {
      return ["and", "or"].includes(operator);
    }
  }]);

  return SFPredicate;
}();

;
var SFPrivileges = exports.SFPrivileges = function (_SFItem) {
  _inherits(SFPrivileges, _SFItem);

  _createClass(SFPrivileges, null, [{
    key: "contentType",
    value: function contentType() {
      // It has prefix SN since it was originally imported from SN codebase
      return "SN|Privileges";
    }
  }]);

  function SFPrivileges(json_obj) {
    _classCallCheck(this, SFPrivileges);

    var _this27 = _possibleConstructorReturn(this, (SFPrivileges.__proto__ || Object.getPrototypeOf(SFPrivileges)).call(this, json_obj));

    if (!_this27.content.desktopPrivileges) {
      _this27.content.desktopPrivileges = {};
    }
    return _this27;
  }

  _createClass(SFPrivileges, [{
    key: "setCredentialsForAction",
    value: function setCredentialsForAction(action, credentials) {
      this.content.desktopPrivileges[action] = credentials;
    }
  }, {
    key: "getCredentialsForAction",
    value: function getCredentialsForAction(action) {
      return this.content.desktopPrivileges[action] || [];
    }
  }, {
    key: "toggleCredentialForAction",
    value: function toggleCredentialForAction(action, credential) {
      if (this.isCredentialRequiredForAction(action, credential)) {
        this.removeCredentialForAction(action, credential);
      } else {
        this.addCredentialForAction(action, credential);
      }
    }
  }, {
    key: "removeCredentialForAction",
    value: function removeCredentialForAction(action, credential) {
      _.pull(this.content.desktopPrivileges[action], credential);
    }
  }, {
    key: "addCredentialForAction",
    value: function addCredentialForAction(action, credential) {
      var credentials = this.getCredentialsForAction(action);
      credentials.push(credential);
      this.setCredentialsForAction(action, credentials);
    }
  }, {
    key: "isCredentialRequiredForAction",
    value: function isCredentialRequiredForAction(action, credential) {
      var credentialsRequired = this.getCredentialsForAction(action);
      return credentialsRequired.includes(credential);
    }
  }]);

  return SFPrivileges;
}(SFItem);

; /*
   Important: This is the only object in the session history domain that is persistable.
    A history session contains one main content object:
   the itemUUIDToItemHistoryMapping. This is a dictionary whose keys are item uuids,
   and each value is an SFItemHistory object.
    Each SFItemHistory object contains an array called `entires` which contain `SFItemHistory` entries (or subclasses, if the
   `SFItemHistory.HistoryEntryClassMapping` class property value is set.)
  */

// See default class values at bottom of this file, including `SFHistorySession.LargeItemEntryAmountThreshold`.

var SFHistorySession = exports.SFHistorySession = function (_SFItem2) {
  _inherits(SFHistorySession, _SFItem2);

  function SFHistorySession(json_obj) {
    _classCallCheck(this, SFHistorySession);

    /*
      Our .content params:
      {
        itemUUIDToItemHistoryMapping
      }
     */

    var _this28 = _possibleConstructorReturn(this, (SFHistorySession.__proto__ || Object.getPrototypeOf(SFHistorySession)).call(this, json_obj));

    if (!_this28.content.itemUUIDToItemHistoryMapping) {
      _this28.content.itemUUIDToItemHistoryMapping = {};
    }

    // When initializing from a json_obj, we want to deserialize the item history JSON into SFItemHistory objects.
    var uuids = Object.keys(_this28.content.itemUUIDToItemHistoryMapping);
    uuids.forEach(function (itemUUID) {
      var itemHistory = _this28.content.itemUUIDToItemHistoryMapping[itemUUID];
      _this28.content.itemUUIDToItemHistoryMapping[itemUUID] = new SFItemHistory(itemHistory);
    });
    return _this28;
  }

  _createClass(SFHistorySession, [{
    key: "addEntryForItem",
    value: function addEntryForItem(item) {
      var itemHistory = this.historyForItem(item);
      var entry = itemHistory.addHistoryEntryForItem(item);
      return entry;
    }
  }, {
    key: "historyForItem",
    value: function historyForItem(item) {
      var history = this.content.itemUUIDToItemHistoryMapping[item.uuid];
      if (!history) {
        history = this.content.itemUUIDToItemHistoryMapping[item.uuid] = new SFItemHistory();
      }
      return history;
    }
  }, {
    key: "clearItemHistory",
    value: function clearItemHistory(item) {
      this.historyForItem(item).clear();
    }
  }, {
    key: "clearAllHistory",
    value: function clearAllHistory() {
      this.content.itemUUIDToItemHistoryMapping = {};
    }
  }, {
    key: "optimizeHistoryForItem",
    value: function optimizeHistoryForItem(item) {
      // Clean up if there are too many revisions. Note SFHistorySession.LargeItemEntryAmountThreshold is the amount of revisions which above, call
      // for an optimization. An optimization may not remove entries above this threshold. It will determine what it should keep and what it shouldn't.
      // So, it is possible to have a threshold of 60 but have 600 entries, if the item history deems those worth keeping.
      var itemHistory = this.historyForItem(item);
      if (itemHistory.entries.length > SFHistorySession.LargeItemEntryAmountThreshold) {
        itemHistory.optimize();
      }
    }
  }]);

  return SFHistorySession;
}(SFItem);

// See comment in `this.optimizeHistoryForItem`


SFHistorySession.LargeItemEntryAmountThreshold = 60;
; // See default class values at bottom of this file, including `SFItemHistory.LargeEntryDeltaThreshold`.

var SFItemHistory = exports.SFItemHistory = function () {
  function SFItemHistory() {
    var params = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, SFItemHistory);

    if (!this.entries) {
      this.entries = [];
    }

    // Deserialize the entries into entry objects.
    if (params.entries) {
      var _iteratorNormalCompletion57 = true;
      var _didIteratorError57 = false;
      var _iteratorError57 = undefined;

      try {
        for (var _iterator57 = params.entries[Symbol.iterator](), _step57; !(_iteratorNormalCompletion57 = (_step57 = _iterator57.next()).done); _iteratorNormalCompletion57 = true) {
          var entryParams = _step57.value;

          var entry = this.createEntryForItem(entryParams.item);
          entry.setPreviousEntry(this.getLastEntry());
          this.entries.push(entry);
        }
      } catch (err) {
        _didIteratorError57 = true;
        _iteratorError57 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion57 && _iterator57.return) {
            _iterator57.return();
          }
        } finally {
          if (_didIteratorError57) {
            throw _iteratorError57;
          }
        }
      }
    }
  }

  _createClass(SFItemHistory, [{
    key: "createEntryForItem",
    value: function createEntryForItem(item) {
      var historyItemClass = SFItemHistory.HistoryEntryClassMapping && SFItemHistory.HistoryEntryClassMapping[item.content_type];
      if (!historyItemClass) {
        historyItemClass = SFItemHistoryEntry;
      }
      var entry = new historyItemClass(item);
      return entry;
    }
  }, {
    key: "getLastEntry",
    value: function getLastEntry() {
      return this.entries[this.entries.length - 1];
    }
  }, {
    key: "addHistoryEntryForItem",
    value: function addHistoryEntryForItem(item) {
      var prospectiveEntry = this.createEntryForItem(item);

      var previousEntry = this.getLastEntry();
      prospectiveEntry.setPreviousEntry(previousEntry);

      // Don't add first revision if text length is 0, as this means it's a new note.
      // Actually, nevermind. If we do this, the first character added to a new note
      // will be displayed as "1 characters loaded".
      // if(!previousRevision && prospectiveRevision.textCharDiffLength == 0) {
      //   return;
      // }

      // Don't add if text is the same
      if (prospectiveEntry.isSameAsEntry(previousEntry)) {
        return;
      }

      this.entries.push(prospectiveEntry);
      return prospectiveEntry;
    }
  }, {
    key: "clear",
    value: function clear() {
      this.entries.length = 0;
    }
  }, {
    key: "optimize",
    value: function optimize() {
      var _this29 = this;

      var keepEntries = [];

      var isEntrySignificant = function isEntrySignificant(entry) {
        return entry.deltaSize() > SFItemHistory.LargeEntryDeltaThreshold;
      };

      var processEntry = function processEntry(entry, index, keep) {
        // Entries may be processed retrospectively, meaning it can be decided to be deleted, then an upcoming processing can change that.
        if (keep) {
          keepEntries.push(entry);
        } else {
          // Remove if in keep
          var index = keepEntries.indexOf(entry);
          if (index !== -1) {
            keepEntries.splice(index, 1);
          }
        }

        if (keep && isEntrySignificant(entry) && entry.operationVector() == -1) {
          // This is a large negative change. Hang on to the previous entry.
          var previousEntry = _this29.entries[index - 1];
          if (previousEntry) {
            keepEntries.push(previousEntry);
          }
        }
      };

      this.entries.forEach(function (entry, index) {
        if (index == 0 || index == _this29.entries.length - 1) {
          // Keep the first and last
          processEntry(entry, index, true);
        } else {
          var significant = isEntrySignificant(entry);
          processEntry(entry, index, significant);
        }
      });

      this.entries = this.entries.filter(function (entry, index) {
        return keepEntries.indexOf(entry) !== -1;
      });
    }
  }]);

  return SFItemHistory;
}();

// The amount of characters added or removed that constitute a keepable entry after optimization.


SFItemHistory.LargeEntryDeltaThreshold = 15;
;
var SFItemHistoryEntry = exports.SFItemHistoryEntry = function () {
  function SFItemHistoryEntry(item) {
    _classCallCheck(this, SFItemHistoryEntry);

    // Whatever values `item` has will be persisted, so be sure that the values are picked beforehand.
    this.item = SFItem.deepMerge({}, item);

    // We'll assume a `text` content value to diff on. If it doesn't exist, no problem.
    this.defaultContentKeyToDiffOn = "text";

    // Default value
    this.textCharDiffLength = 0;

    if (typeof this.item.updated_at == 'string') {
      this.item.updated_at = new Date(this.item.updated_at);
    }
  }

  _createClass(SFItemHistoryEntry, [{
    key: "setPreviousEntry",
    value: function setPreviousEntry(previousEntry) {
      this.hasPreviousEntry = previousEntry != null;

      // we'll try to compute the delta based on an assumed content property of `text`, if it exists.
      if (this.item.content[this.defaultContentKeyToDiffOn]) {
        if (previousEntry) {
          this.textCharDiffLength = this.item.content[this.defaultContentKeyToDiffOn].length - previousEntry.item.content[this.defaultContentKeyToDiffOn].length;
        } else {
          this.textCharDiffLength = this.item.content[this.defaultContentKeyToDiffOn].length;
        }
      }
    }
  }, {
    key: "operationVector",
    value: function operationVector() {
      // We'll try to use the value of `textCharDiffLength` to help determine this, if it's set
      if (this.textCharDiffLength != undefined) {
        if (!this.hasPreviousEntry || this.textCharDiffLength == 0) {
          return 0;
        } else if (this.textCharDiffLength < 0) {
          return -1;
        } else {
          return 1;
        }
      }

      // Otherwise use a default value of 1
      return 1;
    }
  }, {
    key: "deltaSize",
    value: function deltaSize() {
      // Up to the subclass to determine how large the delta was, i.e number of characters changed.
      // But this general class won't be able to determine which property it should diff on, or even its format.

      // We can return the `textCharDiffLength` if it's set, otherwise, just return 1;
      if (this.textCharDiffLength != undefined) {
        return Math.abs(this.textCharDiffLength);
      }

      // Otherwise return 1 here to constitute a basic positive delta.
      // The value returned should always be positive. override `operationVector` to return the direction of the delta.
      return 1;
    }
  }, {
    key: "isSameAsEntry",
    value: function isSameAsEntry(entry) {
      if (!entry) {
        return false;
      }

      var lhs = new SFItem(this.item);
      var rhs = new SFItem(entry.item);
      return lhs.isItemContentEqualWith(rhs);
    }
  }]);

  return SFItemHistoryEntry;
}();

; /* Abstract class. Instantiate an instance of either SFCryptoJS (uses cryptojs) or SFCryptoWeb (uses web crypto) */

var globalScope = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : null;

var SFAbstractCrypto = exports.SFAbstractCrypto = function () {
  function SFAbstractCrypto() {
    _classCallCheck(this, SFAbstractCrypto);

    this.DefaultPBKDF2Length = 768;
  }

  /*
  Our WebCrypto implementation only offers PBKDf2, so any other encryption
  and key generation functions must use CryptoJS in this abstract implementation.
  */

  _createClass(SFAbstractCrypto, [{
    key: "generateUUIDSync",
    value: function generateUUIDSync() {
      var crypto = globalScope.crypto || globalScope.msCrypto;
      if (crypto) {
        var buf = new Uint32Array(4);
        crypto.getRandomValues(buf);
        var idx = -1;
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
          idx++;
          var r = buf[idx >> 3] >> idx % 8 * 4 & 15;
          var v = c == 'x' ? r : r & 0x3 | 0x8;
          return v.toString(16);
        });
      } else {
        var d = new Date().getTime();
        if (globalScope.performance && typeof globalScope.performance.now === "function") {
          d += performance.now(); //use high-precision timer if available
        }
        var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
          var r = (d + Math.random() * 16) % 16 | 0;
          d = Math.floor(d / 16);
          return (c == 'x' ? r : r & 0x3 | 0x8).toString(16);
        });
        return uuid;
      }
    }
  }, {
    key: "generateUUID",
    value: function () {
      var _ref121 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee110() {
        return regeneratorRuntime.wrap(function _callee110$(_context110) {
          while (1) {
            switch (_context110.prev = _context110.next) {
              case 0:
                return _context110.abrupt("return", this.generateUUIDSync());

              case 1:
              case "end":
                return _context110.stop();
            }
          }
        }, _callee110, this);
      }));

      function generateUUID() {
        return _ref121.apply(this, arguments);
      }

      return generateUUID;
    }()
  }, {
    key: "decryptText",
    value: function () {
      var _ref122 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee111() {
        var _ref123 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
            ciphertextToAuth = _ref123.ciphertextToAuth,
            contentCiphertext = _ref123.contentCiphertext,
            encryptionKey = _ref123.encryptionKey,
            iv = _ref123.iv,
            authHash = _ref123.authHash,
            authKey = _ref123.authKey;

        var requiresAuth = arguments[1];
        var localAuthHash, keyData, ivData, decrypted;
        return regeneratorRuntime.wrap(function _callee111$(_context111) {
          while (1) {
            switch (_context111.prev = _context111.next) {
              case 0:
                if (!(requiresAuth && !authHash)) {
                  _context111.next = 3;
                  break;
                }

                console.error("Auth hash is required.");
                return _context111.abrupt("return");

              case 3:
                if (!authHash) {
                  _context111.next = 10;
                  break;
                }

                _context111.next = 6;
                return this.hmac256(ciphertextToAuth, authKey);

              case 6:
                localAuthHash = _context111.sent;

                if (!(authHash !== localAuthHash)) {
                  _context111.next = 10;
                  break;
                }

                console.error("Auth hash does not match, returning null.");
                return _context111.abrupt("return", null);

              case 10:
                keyData = CryptoJS.enc.Hex.parse(encryptionKey);
                ivData = CryptoJS.enc.Hex.parse(iv || "");
                decrypted = CryptoJS.AES.decrypt(contentCiphertext, keyData, { iv: ivData, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
                return _context111.abrupt("return", decrypted.toString(CryptoJS.enc.Utf8));

              case 14:
              case "end":
                return _context111.stop();
            }
          }
        }, _callee111, this);
      }));

      function decryptText() {
        return _ref122.apply(this, arguments);
      }

      return decryptText;
    }()
  }, {
    key: "encryptText",
    value: function () {
      var _ref124 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee112(text, key, iv) {
        var keyData, ivData, encrypted;
        return regeneratorRuntime.wrap(function _callee112$(_context112) {
          while (1) {
            switch (_context112.prev = _context112.next) {
              case 0:
                keyData = CryptoJS.enc.Hex.parse(key);
                ivData = CryptoJS.enc.Hex.parse(iv || "");
                encrypted = CryptoJS.AES.encrypt(text, keyData, { iv: ivData, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
                return _context112.abrupt("return", encrypted.toString());

              case 4:
              case "end":
                return _context112.stop();
            }
          }
        }, _callee112, this);
      }));

      function encryptText(_x134, _x135, _x136) {
        return _ref124.apply(this, arguments);
      }

      return encryptText;
    }()
  }, {
    key: "generateRandomKey",
    value: function () {
      var _ref125 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee113(bits) {
        return regeneratorRuntime.wrap(function _callee113$(_context113) {
          while (1) {
            switch (_context113.prev = _context113.next) {
              case 0:
                return _context113.abrupt("return", CryptoJS.lib.WordArray.random(bits / 8).toString());

              case 1:
              case "end":
                return _context113.stop();
            }
          }
        }, _callee113, this);
      }));

      function generateRandomKey(_x137) {
        return _ref125.apply(this, arguments);
      }

      return generateRandomKey;
    }()
  }, {
    key: "generateItemEncryptionKey",
    value: function () {
      var _ref126 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee114() {
        var length, cost, salt, passphrase;
        return regeneratorRuntime.wrap(function _callee114$(_context114) {
          while (1) {
            switch (_context114.prev = _context114.next) {
              case 0:
                // Generates a key that will be split in half, each being 256 bits. So total length will need to be 512.
                length = 512;
                cost = 1;
                _context114.next = 4;
                return this.generateRandomKey(length);

              case 4:
                salt = _context114.sent;
                _context114.next = 7;
                return this.generateRandomKey(length);

              case 7:
                passphrase = _context114.sent;
                return _context114.abrupt("return", this.pbkdf2(passphrase, salt, cost, length));

              case 9:
              case "end":
                return _context114.stop();
            }
          }
        }, _callee114, this);
      }));

      function generateItemEncryptionKey() {
        return _ref126.apply(this, arguments);
      }

      return generateItemEncryptionKey;
    }()
  }, {
    key: "firstHalfOfKey",
    value: function () {
      var _ref127 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee115(key) {
        return regeneratorRuntime.wrap(function _callee115$(_context115) {
          while (1) {
            switch (_context115.prev = _context115.next) {
              case 0:
                return _context115.abrupt("return", key.substring(0, key.length / 2));

              case 1:
              case "end":
                return _context115.stop();
            }
          }
        }, _callee115, this);
      }));

      function firstHalfOfKey(_x138) {
        return _ref127.apply(this, arguments);
      }

      return firstHalfOfKey;
    }()
  }, {
    key: "secondHalfOfKey",
    value: function () {
      var _ref128 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee116(key) {
        return regeneratorRuntime.wrap(function _callee116$(_context116) {
          while (1) {
            switch (_context116.prev = _context116.next) {
              case 0:
                return _context116.abrupt("return", key.substring(key.length / 2, key.length));

              case 1:
              case "end":
                return _context116.stop();
            }
          }
        }, _callee116, this);
      }));

      function secondHalfOfKey(_x139) {
        return _ref128.apply(this, arguments);
      }

      return secondHalfOfKey;
    }()
  }, {
    key: "base64",
    value: function () {
      var _ref129 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee117(text) {
        return regeneratorRuntime.wrap(function _callee117$(_context117) {
          while (1) {
            switch (_context117.prev = _context117.next) {
              case 0:
                return _context117.abrupt("return", globalScope.btoa(encodeURIComponent(text).replace(/%([0-9A-F]{2})/g, function toSolidBytes(match, p1) {
                  return String.fromCharCode('0x' + p1);
                })));

              case 1:
              case "end":
                return _context117.stop();
            }
          }
        }, _callee117, this);
      }));

      function base64(_x140) {
        return _ref129.apply(this, arguments);
      }

      return base64;
    }()
  }, {
    key: "base64Decode",
    value: function () {
      var _ref130 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee118(base64String) {
        return regeneratorRuntime.wrap(function _callee118$(_context118) {
          while (1) {
            switch (_context118.prev = _context118.next) {
              case 0:
                return _context118.abrupt("return", globalScope.atob(base64String));

              case 1:
              case "end":
                return _context118.stop();
            }
          }
        }, _callee118, this);
      }));

      function base64Decode(_x141) {
        return _ref130.apply(this, arguments);
      }

      return base64Decode;
    }()
  }, {
    key: "sha256",
    value: function () {
      var _ref131 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee119(text) {
        return regeneratorRuntime.wrap(function _callee119$(_context119) {
          while (1) {
            switch (_context119.prev = _context119.next) {
              case 0:
                return _context119.abrupt("return", CryptoJS.SHA256(text).toString());

              case 1:
              case "end":
                return _context119.stop();
            }
          }
        }, _callee119, this);
      }));

      function sha256(_x142) {
        return _ref131.apply(this, arguments);
      }

      return sha256;
    }()
  }, {
    key: "hmac256",
    value: function () {
      var _ref132 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee120(message, key) {
        var keyData, messageData, result;
        return regeneratorRuntime.wrap(function _callee120$(_context120) {
          while (1) {
            switch (_context120.prev = _context120.next) {
              case 0:
                keyData = CryptoJS.enc.Hex.parse(key);
                messageData = CryptoJS.enc.Utf8.parse(message);
                result = CryptoJS.HmacSHA256(messageData, keyData).toString();
                return _context120.abrupt("return", result);

              case 4:
              case "end":
                return _context120.stop();
            }
          }
        }, _callee120, this);
      }));

      function hmac256(_x143, _x144) {
        return _ref132.apply(this, arguments);
      }

      return hmac256;
    }()
  }, {
    key: "generateSalt",
    value: function () {
      var _ref133 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee121(identifier, version, cost, nonce) {
        var result;
        return regeneratorRuntime.wrap(function _callee121$(_context121) {
          while (1) {
            switch (_context121.prev = _context121.next) {
              case 0:
                _context121.next = 2;
                return this.sha256([identifier, "SF", version, cost, nonce].join(":"));

              case 2:
                result = _context121.sent;
                return _context121.abrupt("return", result);

              case 4:
              case "end":
                return _context121.stop();
            }
          }
        }, _callee121, this);
      }));

      function generateSalt(_x145, _x146, _x147, _x148) {
        return _ref133.apply(this, arguments);
      }

      return generateSalt;
    }()

    /** Generates two deterministic keys based on one input */

  }, {
    key: "generateSymmetricKeyPair",
    value: function () {
      var _ref134 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee122() {
        var _ref135 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
            password = _ref135.password,
            pw_salt = _ref135.pw_salt,
            pw_cost = _ref135.pw_cost;

        var output, outputLength, splitLength, firstThird, secondThird, thirdThird;
        return regeneratorRuntime.wrap(function _callee122$(_context122) {
          while (1) {
            switch (_context122.prev = _context122.next) {
              case 0:
                _context122.next = 2;
                return this.pbkdf2(password, pw_salt, pw_cost, this.DefaultPBKDF2Length);

              case 2:
                output = _context122.sent;
                outputLength = output.length;
                splitLength = outputLength / 3;
                firstThird = output.slice(0, splitLength);
                secondThird = output.slice(splitLength, splitLength * 2);
                thirdThird = output.slice(splitLength * 2, splitLength * 3);
                return _context122.abrupt("return", [firstThird, secondThird, thirdThird]);

              case 9:
              case "end":
                return _context122.stop();
            }
          }
        }, _callee122, this);
      }));

      function generateSymmetricKeyPair() {
        return _ref134.apply(this, arguments);
      }

      return generateSymmetricKeyPair;
    }()
  }, {
    key: "computeEncryptionKeysForUser",
    value: function () {
      var _ref136 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee123(password, authParams) {
        var pw_salt;
        return regeneratorRuntime.wrap(function _callee123$(_context123) {
          while (1) {
            switch (_context123.prev = _context123.next) {
              case 0:
                if (!(authParams.version == "003")) {
                  _context123.next = 9;
                  break;
                }

                if (authParams.identifier) {
                  _context123.next = 4;
                  break;
                }

                console.error("authParams is missing identifier.");
                return _context123.abrupt("return");

              case 4:
                _context123.next = 6;
                return this.generateSalt(authParams.identifier, authParams.version, authParams.pw_cost, authParams.pw_nonce);

              case 6:
                pw_salt = _context123.sent;
                _context123.next = 10;
                break;

              case 9:
                // Salt is returned from server
                pw_salt = authParams.pw_salt;

              case 10:
                return _context123.abrupt("return", this.generateSymmetricKeyPair({ password: password, pw_salt: pw_salt, pw_cost: authParams.pw_cost }).then(function (keys) {
                  var userKeys = { pw: keys[0], mk: keys[1], ak: keys[2] };
                  return userKeys;
                }));

              case 11:
              case "end":
                return _context123.stop();
            }
          }
        }, _callee123, this);
      }));

      function computeEncryptionKeysForUser(_x150, _x151) {
        return _ref136.apply(this, arguments);
      }

      return computeEncryptionKeysForUser;
    }()

    // Unlike computeEncryptionKeysForUser, this method always uses the latest SF Version

  }, {
    key: "generateInitialKeysAndAuthParamsForUser",
    value: function () {
      var _ref137 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee124(identifier, password) {
        var version, pw_cost, pw_nonce, pw_salt;
        return regeneratorRuntime.wrap(function _callee124$(_context124) {
          while (1) {
            switch (_context124.prev = _context124.next) {
              case 0:
                version = this.SFJS.version;
                pw_cost = this.SFJS.defaultPasswordGenerationCost;
                _context124.next = 4;
                return this.generateRandomKey(256);

              case 4:
                pw_nonce = _context124.sent;
                _context124.next = 7;
                return this.generateSalt(identifier, version, pw_cost, pw_nonce);

              case 7:
                pw_salt = _context124.sent;
                return _context124.abrupt("return", this.generateSymmetricKeyPair({ password: password, pw_salt: pw_salt, pw_cost: pw_cost }).then(function (keys) {
                  var authParams = { pw_nonce: pw_nonce, pw_cost: pw_cost, identifier: identifier, version: version };
                  var userKeys = { pw: keys[0], mk: keys[1], ak: keys[2] };
                  return { keys: userKeys, authParams: authParams };
                }));

              case 9:
              case "end":
                return _context124.stop();
            }
          }
        }, _callee124, this);
      }));

      function generateInitialKeysAndAuthParamsForUser(_x152, _x153) {
        return _ref137.apply(this, arguments);
      }

      return generateInitialKeysAndAuthParamsForUser;
    }()
  }]);

  return SFAbstractCrypto;
}();

;
var SFCryptoJS = exports.SFCryptoJS = function (_SFAbstractCrypto) {
  _inherits(SFCryptoJS, _SFAbstractCrypto);

  function SFCryptoJS() {
    _classCallCheck(this, SFCryptoJS);

    return _possibleConstructorReturn(this, (SFCryptoJS.__proto__ || Object.getPrototypeOf(SFCryptoJS)).apply(this, arguments));
  }

  _createClass(SFCryptoJS, [{
    key: "pbkdf2",
    value: function () {
      var _ref138 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee125(password, pw_salt, pw_cost, length) {
        var params;
        return regeneratorRuntime.wrap(function _callee125$(_context125) {
          while (1) {
            switch (_context125.prev = _context125.next) {
              case 0:
                params = {
                  keySize: length / 32,
                  hasher: CryptoJS.algo.SHA512,
                  iterations: pw_cost
                };
                return _context125.abrupt("return", CryptoJS.PBKDF2(password, pw_salt, params).toString());

              case 2:
              case "end":
                return _context125.stop();
            }
          }
        }, _callee125, this);
      }));

      function pbkdf2(_x154, _x155, _x156, _x157) {
        return _ref138.apply(this, arguments);
      }

      return pbkdf2;
    }()
  }]);

  return SFCryptoJS;
}(SFAbstractCrypto);

;var globalScope = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : null;

var subtleCrypto = globalScope.crypto ? globalScope.crypto.subtle : null;

var SFCryptoWeb = exports.SFCryptoWeb = function (_SFAbstractCrypto2) {
  _inherits(SFCryptoWeb, _SFAbstractCrypto2);

  function SFCryptoWeb() {
    _classCallCheck(this, SFCryptoWeb);

    return _possibleConstructorReturn(this, (SFCryptoWeb.__proto__ || Object.getPrototypeOf(SFCryptoWeb)).apply(this, arguments));
  }

  _createClass(SFCryptoWeb, [{
    key: "pbkdf2",


    /**
    Public
    */

    value: function () {
      var _ref139 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee126(password, pw_salt, pw_cost, length) {
        var key;
        return regeneratorRuntime.wrap(function _callee126$(_context126) {
          while (1) {
            switch (_context126.prev = _context126.next) {
              case 0:
                _context126.next = 2;
                return this.webCryptoImportKey(password, "PBKDF2", ["deriveBits"]);

              case 2:
                key = _context126.sent;

                if (key) {
                  _context126.next = 6;
                  break;
                }

                console.log("Key is null, unable to continue");
                return _context126.abrupt("return", null);

              case 6:
                return _context126.abrupt("return", this.webCryptoDeriveBits(key, pw_salt, pw_cost, length));

              case 7:
              case "end":
                return _context126.stop();
            }
          }
        }, _callee126, this);
      }));

      function pbkdf2(_x158, _x159, _x160, _x161) {
        return _ref139.apply(this, arguments);
      }

      return pbkdf2;
    }()
  }, {
    key: "generateRandomKey",
    value: function () {
      var _ref140 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee128(bits) {
        var _this32 = this;

        var extractable;
        return regeneratorRuntime.wrap(function _callee128$(_context128) {
          while (1) {
            switch (_context128.prev = _context128.next) {
              case 0:
                extractable = true;
                return _context128.abrupt("return", subtleCrypto.generateKey({ name: "AES-CBC", length: bits }, extractable, ["encrypt", "decrypt"]).then(function (keyObject) {
                  return subtleCrypto.exportKey("raw", keyObject).then(function () {
                    var _ref141 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee127(keyData) {
                      var key;
                      return regeneratorRuntime.wrap(function _callee127$(_context127) {
                        while (1) {
                          switch (_context127.prev = _context127.next) {
                            case 0:
                              _context127.next = 2;
                              return _this32.arrayBufferToHexString(new Uint8Array(keyData));

                            case 2:
                              key = _context127.sent;
                              return _context127.abrupt("return", key);

                            case 4:
                            case "end":
                              return _context127.stop();
                          }
                        }
                      }, _callee127, _this32);
                    }));

                    return function (_x163) {
                      return _ref141.apply(this, arguments);
                    };
                  }()).catch(function (err) {
                    console.error("Error exporting key", err);
                  });
                }).catch(function (err) {
                  console.error("Error generating key", err);
                }));

              case 2:
              case "end":
                return _context128.stop();
            }
          }
        }, _callee128, this);
      }));

      function generateRandomKey(_x162) {
        return _ref140.apply(this, arguments);
      }

      return generateRandomKey;
    }()
  }, {
    key: "generateItemEncryptionKey",
    value: function () {
      var _ref142 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee129() {
        var length;
        return regeneratorRuntime.wrap(function _callee129$(_context129) {
          while (1) {
            switch (_context129.prev = _context129.next) {
              case 0:
                // Generates a key that will be split in half, each being 256 bits. So total length will need to be 512.
                length = 256;
                return _context129.abrupt("return", Promise.all([this.generateRandomKey(length), this.generateRandomKey(length)]).then(function (values) {
                  return values.join("");
                }));

              case 2:
              case "end":
                return _context129.stop();
            }
          }
        }, _callee129, this);
      }));

      function generateItemEncryptionKey() {
        return _ref142.apply(this, arguments);
      }

      return generateItemEncryptionKey;
    }()

    /* This is a functioning implementation of WebCrypto's encrypt, however, in basic testing, CrpytoJS performs about 30-40% faster, surprisingly. */

  }, {
    key: "encryptText",
    value: function () {
      var _ref143 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee131(text, key, iv) {
        var _this33 = this;

        var ivData, alg, keyBuffer, keyData, textData;
        return regeneratorRuntime.wrap(function _callee131$(_context131) {
          while (1) {
            switch (_context131.prev = _context131.next) {
              case 0:
                if (!iv) {
                  _context131.next = 6;
                  break;
                }

                _context131.next = 3;
                return this.hexStringToArrayBuffer(iv);

              case 3:
                _context131.t0 = _context131.sent;
                _context131.next = 7;
                break;

              case 6:
                _context131.t0 = new ArrayBuffer(16);

              case 7:
                ivData = _context131.t0;
                alg = { name: 'AES-CBC', iv: ivData };
                _context131.next = 11;
                return this.hexStringToArrayBuffer(key);

              case 11:
                keyBuffer = _context131.sent;
                _context131.next = 14;
                return this.webCryptoImportKey(keyBuffer, alg.name, ["encrypt"]);

              case 14:
                keyData = _context131.sent;
                _context131.next = 17;
                return this.stringToArrayBuffer(text);

              case 17:
                textData = _context131.sent;
                return _context131.abrupt("return", crypto.subtle.encrypt(alg, keyData, textData).then(function () {
                  var _ref144 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee130(result) {
                    var cipher;
                    return regeneratorRuntime.wrap(function _callee130$(_context130) {
                      while (1) {
                        switch (_context130.prev = _context130.next) {
                          case 0:
                            _context130.next = 2;
                            return _this33.arrayBufferToBase64(result);

                          case 2:
                            cipher = _context130.sent;
                            return _context130.abrupt("return", cipher);

                          case 4:
                          case "end":
                            return _context130.stop();
                        }
                      }
                    }, _callee130, _this33);
                  }));

                  return function (_x167) {
                    return _ref144.apply(this, arguments);
                  };
                }()));

              case 19:
              case "end":
                return _context131.stop();
            }
          }
        }, _callee131, this);
      }));

      function encryptText(_x164, _x165, _x166) {
        return _ref143.apply(this, arguments);
      }

      return encryptText;
    }()
  }, {
    key: "decryptText",
    value: function () {
      var _ref145 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee133() {
        var _this34 = this;

        var _ref146 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
            ciphertextToAuth = _ref146.ciphertextToAuth,
            contentCiphertext = _ref146.contentCiphertext,
            encryptionKey = _ref146.encryptionKey,
            iv = _ref146.iv,
            authHash = _ref146.authHash,
            authKey = _ref146.authKey;

        var requiresAuth = arguments[1];
        var localAuthHash, ivData, alg, keyBuffer, keyData, textData;
        return regeneratorRuntime.wrap(function _callee133$(_context133) {
          while (1) {
            switch (_context133.prev = _context133.next) {
              case 0:
                if (!(requiresAuth && !authHash)) {
                  _context133.next = 3;
                  break;
                }

                console.error("Auth hash is required.");
                return _context133.abrupt("return");

              case 3:
                if (!authHash) {
                  _context133.next = 10;
                  break;
                }

                _context133.next = 6;
                return this.hmac256(ciphertextToAuth, authKey);

              case 6:
                localAuthHash = _context133.sent;

                if (!(authHash !== localAuthHash)) {
                  _context133.next = 10;
                  break;
                }

                console.error("Auth hash does not match, returning null. " + authHash + " != " + localAuthHash);
                return _context133.abrupt("return", null);

              case 10:
                if (!iv) {
                  _context133.next = 16;
                  break;
                }

                _context133.next = 13;
                return this.hexStringToArrayBuffer(iv);

              case 13:
                _context133.t0 = _context133.sent;
                _context133.next = 17;
                break;

              case 16:
                _context133.t0 = new ArrayBuffer(16);

              case 17:
                ivData = _context133.t0;
                alg = { name: 'AES-CBC', iv: ivData };
                _context133.next = 21;
                return this.hexStringToArrayBuffer(encryptionKey);

              case 21:
                keyBuffer = _context133.sent;
                _context133.next = 24;
                return this.webCryptoImportKey(keyBuffer, alg.name, ["decrypt"]);

              case 24:
                keyData = _context133.sent;
                _context133.next = 27;
                return this.base64ToArrayBuffer(contentCiphertext);

              case 27:
                textData = _context133.sent;
                return _context133.abrupt("return", crypto.subtle.decrypt(alg, keyData, textData).then(function () {
                  var _ref147 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee132(result) {
                    var decoded;
                    return regeneratorRuntime.wrap(function _callee132$(_context132) {
                      while (1) {
                        switch (_context132.prev = _context132.next) {
                          case 0:
                            _context132.next = 2;
                            return _this34.arrayBufferToString(result);

                          case 2:
                            decoded = _context132.sent;
                            return _context132.abrupt("return", decoded);

                          case 4:
                          case "end":
                            return _context132.stop();
                        }
                      }
                    }, _callee132, _this34);
                  }));

                  return function (_x169) {
                    return _ref147.apply(this, arguments);
                  };
                }()).catch(function (error) {
                  console.error("Error decrypting:", error);
                }));

              case 29:
              case "end":
                return _context133.stop();
            }
          }
        }, _callee133, this);
      }));

      function decryptText() {
        return _ref145.apply(this, arguments);
      }

      return decryptText;
    }()

    /**
    Internal
    */

  }, {
    key: "webCryptoImportKey",
    value: function () {
      var _ref148 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee134(input, alg, actions, hash) {
        var text;
        return regeneratorRuntime.wrap(function _callee134$(_context134) {
          while (1) {
            switch (_context134.prev = _context134.next) {
              case 0:
                if (!(typeof input === "string")) {
                  _context134.next = 6;
                  break;
                }

                _context134.next = 3;
                return this.stringToArrayBuffer(input);

              case 3:
                _context134.t0 = _context134.sent;
                _context134.next = 7;
                break;

              case 6:
                _context134.t0 = input;

              case 7:
                text = _context134.t0;
                return _context134.abrupt("return", subtleCrypto.importKey("raw", text, { name: alg, hash: hash }, false, actions).then(function (key) {
                  return key;
                }).catch(function (err) {
                  console.error(err);
                  return null;
                }));

              case 9:
              case "end":
                return _context134.stop();
            }
          }
        }, _callee134, this);
      }));

      function webCryptoImportKey(_x170, _x171, _x172, _x173) {
        return _ref148.apply(this, arguments);
      }

      return webCryptoImportKey;
    }()
    //

  }, {
    key: "webCryptoDeriveBits",
    value: function () {
      var _ref149 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee136(key, pw_salt, pw_cost, length) {
        var _this35 = this;

        var params;
        return regeneratorRuntime.wrap(function _callee136$(_context136) {
          while (1) {
            switch (_context136.prev = _context136.next) {
              case 0:
                _context136.next = 2;
                return this.stringToArrayBuffer(pw_salt);

              case 2:
                _context136.t0 = _context136.sent;
                _context136.t1 = pw_cost;
                _context136.t2 = { name: "SHA-512" };
                params = {
                  "name": "PBKDF2",
                  salt: _context136.t0,
                  iterations: _context136.t1,
                  hash: _context136.t2
                };
                return _context136.abrupt("return", subtleCrypto.deriveBits(params, key, length).then(function () {
                  var _ref150 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee135(bits) {
                    var key;
                    return regeneratorRuntime.wrap(function _callee135$(_context135) {
                      while (1) {
                        switch (_context135.prev = _context135.next) {
                          case 0:
                            _context135.next = 2;
                            return _this35.arrayBufferToHexString(new Uint8Array(bits));

                          case 2:
                            key = _context135.sent;
                            return _context135.abrupt("return", key);

                          case 4:
                          case "end":
                            return _context135.stop();
                        }
                      }
                    }, _callee135, _this35);
                  }));

                  return function (_x178) {
                    return _ref150.apply(this, arguments);
                  };
                }()).catch(function (err) {
                  console.error(err);
                  return null;
                }));

              case 7:
              case "end":
                return _context136.stop();
            }
          }
        }, _callee136, this);
      }));

      function webCryptoDeriveBits(_x174, _x175, _x176, _x177) {
        return _ref149.apply(this, arguments);
      }

      return webCryptoDeriveBits;
    }()
  }, {
    key: "stringToArrayBuffer",
    value: function () {
      var _ref151 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee137(string) {
        return regeneratorRuntime.wrap(function _callee137$(_context137) {
          while (1) {
            switch (_context137.prev = _context137.next) {
              case 0:
                return _context137.abrupt("return", new Promise(function (resolve, reject) {
                  var blob = new Blob([string]);
                  var f = new FileReader();
                  f.onload = function (e) {
                    resolve(e.target.result);
                  };
                  f.readAsArrayBuffer(blob);
                }));

              case 1:
              case "end":
                return _context137.stop();
            }
          }
        }, _callee137, this);
      }));

      function stringToArrayBuffer(_x179) {
        return _ref151.apply(this, arguments);
      }

      return stringToArrayBuffer;
    }()
  }, {
    key: "arrayBufferToString",
    value: function () {
      var _ref152 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee138(arrayBuffer) {
        return regeneratorRuntime.wrap(function _callee138$(_context138) {
          while (1) {
            switch (_context138.prev = _context138.next) {
              case 0:
                return _context138.abrupt("return", new Promise(function (resolve, reject) {
                  var blob = new Blob([arrayBuffer]);
                  var f = new FileReader();
                  f.onload = function (e) {
                    resolve(e.target.result);
                  };
                  f.readAsText(blob);
                }));

              case 1:
              case "end":
                return _context138.stop();
            }
          }
        }, _callee138, this);
      }));

      function arrayBufferToString(_x180) {
        return _ref152.apply(this, arguments);
      }

      return arrayBufferToString;
    }()
  }, {
    key: "arrayBufferToHexString",
    value: function () {
      var _ref153 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee139(arrayBuffer) {
        var byteArray, hexString, nextHexByte, i;
        return regeneratorRuntime.wrap(function _callee139$(_context139) {
          while (1) {
            switch (_context139.prev = _context139.next) {
              case 0:
                byteArray = new Uint8Array(arrayBuffer);
                hexString = "";


                for (i = 0; i < byteArray.byteLength; i++) {
                  nextHexByte = byteArray[i].toString(16);
                  if (nextHexByte.length < 2) {
                    nextHexByte = "0" + nextHexByte;
                  }
                  hexString += nextHexByte;
                }
                return _context139.abrupt("return", hexString);

              case 4:
              case "end":
                return _context139.stop();
            }
          }
        }, _callee139, this);
      }));

      function arrayBufferToHexString(_x181) {
        return _ref153.apply(this, arguments);
      }

      return arrayBufferToHexString;
    }()
  }, {
    key: "hexStringToArrayBuffer",
    value: function () {
      var _ref154 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee140(hex) {
        var bytes, c;
        return regeneratorRuntime.wrap(function _callee140$(_context140) {
          while (1) {
            switch (_context140.prev = _context140.next) {
              case 0:
                for (bytes = [], c = 0; c < hex.length; c += 2) {
                  bytes.push(parseInt(hex.substr(c, 2), 16));
                }return _context140.abrupt("return", new Uint8Array(bytes));

              case 2:
              case "end":
                return _context140.stop();
            }
          }
        }, _callee140, this);
      }));

      function hexStringToArrayBuffer(_x182) {
        return _ref154.apply(this, arguments);
      }

      return hexStringToArrayBuffer;
    }()
  }, {
    key: "base64ToArrayBuffer",
    value: function () {
      var _ref155 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee141(base64) {
        var binary_string, len, bytes, i;
        return regeneratorRuntime.wrap(function _callee141$(_context141) {
          while (1) {
            switch (_context141.prev = _context141.next) {
              case 0:
                _context141.next = 2;
                return this.base64Decode(base64);

              case 2:
                binary_string = _context141.sent;
                len = binary_string.length;
                bytes = new Uint8Array(len);

                for (i = 0; i < len; i++) {
                  bytes[i] = binary_string.charCodeAt(i);
                }
                return _context141.abrupt("return", bytes.buffer);

              case 7:
              case "end":
                return _context141.stop();
            }
          }
        }, _callee141, this);
      }));

      function base64ToArrayBuffer(_x183) {
        return _ref155.apply(this, arguments);
      }

      return base64ToArrayBuffer;
    }()
  }, {
    key: "arrayBufferToBase64",
    value: function () {
      var _ref156 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee142(buffer) {
        return regeneratorRuntime.wrap(function _callee142$(_context142) {
          while (1) {
            switch (_context142.prev = _context142.next) {
              case 0:
                return _context142.abrupt("return", new Promise(function (resolve, reject) {
                  var blob = new Blob([buffer], { type: 'application/octet-binary' });
                  var reader = new FileReader();
                  reader.onload = function (evt) {
                    var dataurl = evt.target.result;
                    resolve(dataurl.substr(dataurl.indexOf(',') + 1));
                  };
                  reader.readAsDataURL(blob);
                }));

              case 1:
              case "end":
                return _context142.stop();
            }
          }
        }, _callee142, this);
      }));

      function arrayBufferToBase64(_x184) {
        return _ref156.apply(this, arguments);
      }

      return arrayBufferToBase64;
    }()
  }, {
    key: "hmac256",
    value: function () {
      var _ref157 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee144(message, key) {
        var _this36 = this;

        var keyHexData, keyData, messageData;
        return regeneratorRuntime.wrap(function _callee144$(_context144) {
          while (1) {
            switch (_context144.prev = _context144.next) {
              case 0:
                _context144.next = 2;
                return this.hexStringToArrayBuffer(key);

              case 2:
                keyHexData = _context144.sent;
                _context144.next = 5;
                return this.webCryptoImportKey(keyHexData, "HMAC", ["sign"], { name: "SHA-256" });

              case 5:
                keyData = _context144.sent;
                _context144.next = 8;
                return this.stringToArrayBuffer(message);

              case 8:
                messageData = _context144.sent;
                return _context144.abrupt("return", crypto.subtle.sign({ name: "HMAC" }, keyData, messageData).then(function () {
                  var _ref158 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee143(signature) {
                    var hash;
                    return regeneratorRuntime.wrap(function _callee143$(_context143) {
                      while (1) {
                        switch (_context143.prev = _context143.next) {
                          case 0:
                            _context143.next = 2;
                            return _this36.arrayBufferToHexString(signature);

                          case 2:
                            hash = _context143.sent;
                            return _context143.abrupt("return", hash);

                          case 4:
                          case "end":
                            return _context143.stop();
                        }
                      }
                    }, _callee143, _this36);
                  }));

                  return function (_x187) {
                    return _ref158.apply(this, arguments);
                  };
                }()).catch(function (err) {
                  console.error("Error computing hmac", err);
                }));

              case 10:
              case "end":
                return _context144.stop();
            }
          }
        }, _callee144, this);
      }));

      function hmac256(_x185, _x186) {
        return _ref157.apply(this, arguments);
      }

      return hmac256;
    }()
  }]);

  return SFCryptoWeb;
}(SFAbstractCrypto);

;
var SFItemTransformer = exports.SFItemTransformer = function () {
  function SFItemTransformer(crypto) {
    _classCallCheck(this, SFItemTransformer);

    this.crypto = crypto;
  }

  _createClass(SFItemTransformer, [{
    key: "_private_encryptString",
    value: function () {
      var _ref159 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee145(string, encryptionKey, authKey, uuid, auth_params) {
        var fullCiphertext, contentCiphertext, iv, ciphertextToAuth, authHash, authParamsString;
        return regeneratorRuntime.wrap(function _callee145$(_context145) {
          while (1) {
            switch (_context145.prev = _context145.next) {
              case 0:
                if (!(auth_params.version === "001")) {
                  _context145.next = 7;
                  break;
                }

                _context145.next = 3;
                return this.crypto.encryptText(string, encryptionKey, null);

              case 3:
                contentCiphertext = _context145.sent;

                fullCiphertext = auth_params.version + contentCiphertext;
                _context145.next = 21;
                break;

              case 7:
                _context145.next = 9;
                return this.crypto.generateRandomKey(128);

              case 9:
                iv = _context145.sent;
                _context145.next = 12;
                return this.crypto.encryptText(string, encryptionKey, iv);

              case 12:
                contentCiphertext = _context145.sent;
                ciphertextToAuth = [auth_params.version, uuid, iv, contentCiphertext].join(":");
                _context145.next = 16;
                return this.crypto.hmac256(ciphertextToAuth, authKey);

              case 16:
                authHash = _context145.sent;
                _context145.next = 19;
                return this.crypto.base64(JSON.stringify(auth_params));

              case 19:
                authParamsString = _context145.sent;

                fullCiphertext = [auth_params.version, authHash, uuid, iv, contentCiphertext, authParamsString].join(":");

              case 21:
                return _context145.abrupt("return", fullCiphertext);

              case 22:
              case "end":
                return _context145.stop();
            }
          }
        }, _callee145, this);
      }));

      function _private_encryptString(_x188, _x189, _x190, _x191, _x192) {
        return _ref159.apply(this, arguments);
      }

      return _private_encryptString;
    }()
  }, {
    key: "encryptItem",
    value: function () {
      var _ref160 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee146(item, keys, auth_params) {
        var params, item_key, ek, ak, ciphertext, authHash;
        return regeneratorRuntime.wrap(function _callee146$(_context146) {
          while (1) {
            switch (_context146.prev = _context146.next) {
              case 0:
                params = {};
                // encrypt item key

                _context146.next = 3;
                return this.crypto.generateItemEncryptionKey();

              case 3:
                item_key = _context146.sent;

                if (!(auth_params.version === "001")) {
                  _context146.next = 10;
                  break;
                }

                _context146.next = 7;
                return this.crypto.encryptText(item_key, keys.mk, null);

              case 7:
                params.enc_item_key = _context146.sent;
                _context146.next = 13;
                break;

              case 10:
                _context146.next = 12;
                return this._private_encryptString(item_key, keys.mk, keys.ak, item.uuid, auth_params);

              case 12:
                params.enc_item_key = _context146.sent;

              case 13:
                _context146.next = 15;
                return this.crypto.firstHalfOfKey(item_key);

              case 15:
                ek = _context146.sent;
                _context146.next = 18;
                return this.crypto.secondHalfOfKey(item_key);

              case 18:
                ak = _context146.sent;
                _context146.next = 21;
                return this._private_encryptString(JSON.stringify(item.createContentJSONFromProperties()), ek, ak, item.uuid, auth_params);

              case 21:
                ciphertext = _context146.sent;

                if (!(auth_params.version === "001")) {
                  _context146.next = 27;
                  break;
                }

                _context146.next = 25;
                return this.crypto.hmac256(ciphertext, ak);

              case 25:
                authHash = _context146.sent;

                params.auth_hash = authHash;

              case 27:

                params.content = ciphertext;
                return _context146.abrupt("return", params);

              case 29:
              case "end":
                return _context146.stop();
            }
          }
        }, _callee146, this);
      }));

      function encryptItem(_x193, _x194, _x195) {
        return _ref160.apply(this, arguments);
      }

      return encryptItem;
    }()
  }, {
    key: "encryptionComponentsFromString",
    value: function encryptionComponentsFromString(string, encryptionKey, authKey) {
      var encryptionVersion = string.substring(0, 3);
      if (encryptionVersion === "001") {
        return {
          contentCiphertext: string.substring(3, string.length),
          encryptionVersion: encryptionVersion,
          ciphertextToAuth: string,
          iv: null,
          authHash: null,
          encryptionKey: encryptionKey,
          authKey: authKey
        };
      } else {
        var components = string.split(":");
        return {
          encryptionVersion: components[0],
          authHash: components[1],
          uuid: components[2],
          iv: components[3],
          contentCiphertext: components[4],
          authParams: components[5],
          ciphertextToAuth: [components[0], components[2], components[3], components[4]].join(":"),
          encryptionKey: encryptionKey,
          authKey: authKey
        };
      }
    }
  }, {
    key: "decryptItem",
    value: function () {
      var _ref161 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee147(item, keys) {
        var encryptedItemKey, requiresAuth, keyParams, item_key, ek, ak, itemParams, content;
        return regeneratorRuntime.wrap(function _callee147$(_context147) {
          while (1) {
            switch (_context147.prev = _context147.next) {
              case 0:
                if (!(typeof item.content != "string")) {
                  _context147.next = 2;
                  break;
                }

                return _context147.abrupt("return");

              case 2:
                if (!item.content.startsWith("000")) {
                  _context147.next = 14;
                  break;
                }

                _context147.prev = 3;
                _context147.t0 = JSON;
                _context147.next = 7;
                return this.crypto.base64Decode(item.content.substring(3, item.content.length));

              case 7:
                _context147.t1 = _context147.sent;
                item.content = _context147.t0.parse.call(_context147.t0, _context147.t1);
                _context147.next = 13;
                break;

              case 11:
                _context147.prev = 11;
                _context147.t2 = _context147["catch"](3);

              case 13:
                return _context147.abrupt("return");

              case 14:
                if (item.enc_item_key) {
                  _context147.next = 17;
                  break;
                }

                // This needs to be here to continue, return otherwise
                console.log("Missing item encryption key, skipping decryption.");
                return _context147.abrupt("return");

              case 17:

                // decrypt encrypted key
                encryptedItemKey = item.enc_item_key;
                requiresAuth = true;

                if (!encryptedItemKey.startsWith("002") && !encryptedItemKey.startsWith("003")) {
                  // legacy encryption type, has no prefix
                  encryptedItemKey = "001" + encryptedItemKey;
                  requiresAuth = false;
                }
                keyParams = this.encryptionComponentsFromString(encryptedItemKey, keys.mk, keys.ak);

                // return if uuid in auth hash does not match item uuid. Signs of tampering.

                if (!(keyParams.uuid && keyParams.uuid !== item.uuid)) {
                  _context147.next = 26;
                  break;
                }

                console.error("Item key params UUID does not match item UUID");
                if (!item.errorDecrypting) {
                  item.errorDecryptingValueChanged = true;
                }
                item.errorDecrypting = true;
                return _context147.abrupt("return");

              case 26:
                _context147.next = 28;
                return this.crypto.decryptText(keyParams, requiresAuth);

              case 28:
                item_key = _context147.sent;

                if (item_key) {
                  _context147.next = 34;
                  break;
                }

                console.log("Error decrypting item", item);
                if (!item.errorDecrypting) {
                  item.errorDecryptingValueChanged = true;
                }
                item.errorDecrypting = true;
                return _context147.abrupt("return");

              case 34:
                _context147.next = 36;
                return this.crypto.firstHalfOfKey(item_key);

              case 36:
                ek = _context147.sent;
                _context147.next = 39;
                return this.crypto.secondHalfOfKey(item_key);

              case 39:
                ak = _context147.sent;
                itemParams = this.encryptionComponentsFromString(item.content, ek, ak);
                _context147.prev = 41;
                _context147.t3 = JSON;
                _context147.next = 45;
                return this.crypto.base64Decode(itemParams.authParams);

              case 45:
                _context147.t4 = _context147.sent;
                item.auth_params = _context147.t3.parse.call(_context147.t3, _context147.t4);
                _context147.next = 51;
                break;

              case 49:
                _context147.prev = 49;
                _context147.t5 = _context147["catch"](41);

              case 51:
                if (!(itemParams.uuid && itemParams.uuid !== item.uuid)) {
                  _context147.next = 55;
                  break;
                }

                if (!item.errorDecrypting) {
                  item.errorDecryptingValueChanged = true;
                }
                item.errorDecrypting = true;
                return _context147.abrupt("return");

              case 55:

                if (!itemParams.authHash) {
                  // legacy 001
                  itemParams.authHash = item.auth_hash;
                }

                _context147.next = 58;
                return this.crypto.decryptText(itemParams, true);

              case 58:
                content = _context147.sent;

                if (!content) {
                  if (!item.errorDecrypting) {
                    item.errorDecryptingValueChanged = true;
                  }
                  item.errorDecrypting = true;
                } else {
                  if (item.errorDecrypting == true) {
                    item.errorDecryptingValueChanged = true;
                  }
                  // Content should only be set if it was successfully decrypted, and should otherwise remain unchanged.
                  item.errorDecrypting = false;
                  item.content = content;
                }

              case 60:
              case "end":
                return _context147.stop();
            }
          }
        }, _callee147, this, [[3, 11], [41, 49]]);
      }));

      function decryptItem(_x196, _x197) {
        return _ref161.apply(this, arguments);
      }

      return decryptItem;
    }()
  }, {
    key: "decryptMultipleItems",
    value: function () {
      var _ref162 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee149(items, keys, throws) {
        var _this37 = this;

        var decrypt;
        return regeneratorRuntime.wrap(function _callee149$(_context149) {
          while (1) {
            switch (_context149.prev = _context149.next) {
              case 0:
                decrypt = function () {
                  var _ref163 = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee148(item) {
                    var isString;
                    return regeneratorRuntime.wrap(function _callee148$(_context148) {
                      while (1) {
                        switch (_context148.prev = _context148.next) {
                          case 0:
                            if (item) {
                              _context148.next = 2;
                              break;
                            }

                            return _context148.abrupt("return");

                          case 2:
                            if (!(item.deleted == true && item.content == null)) {
                              _context148.next = 4;
                              break;
                            }

                            return _context148.abrupt("return");

                          case 4:
                            isString = typeof item.content === 'string' || item.content instanceof String;

                            if (!isString) {
                              _context148.next = 19;
                              break;
                            }

                            _context148.prev = 6;
                            _context148.next = 9;
                            return _this37.decryptItem(item, keys);

                          case 9:
                            _context148.next = 19;
                            break;

                          case 11:
                            _context148.prev = 11;
                            _context148.t0 = _context148["catch"](6);

                            if (!item.errorDecrypting) {
                              item.errorDecryptingValueChanged = true;
                            }
                            item.errorDecrypting = true;

                            if (!throws) {
                              _context148.next = 17;
                              break;
                            }

                            throw _context148.t0;

                          case 17:
                            console.error("Error decrypting item", item, _context148.t0);
                            return _context148.abrupt("return");

                          case 19:
                          case "end":
                            return _context148.stop();
                        }
                      }
                    }, _callee148, _this37, [[6, 11]]);
                  }));

                  return function decrypt(_x201) {
                    return _ref163.apply(this, arguments);
                  };
                }();

                return _context149.abrupt("return", Promise.all(items.map(function (item) {
                  return decrypt(item);
                })));

              case 2:
              case "end":
                return _context149.stop();
            }
          }
        }, _callee149, this);
      }));

      function decryptMultipleItems(_x198, _x199, _x200) {
        return _ref162.apply(this, arguments);
      }

      return decryptMultipleItems;
    }()
  }]);

  return SFItemTransformer;
}();

;var globalScope = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : null;

var StandardFile = exports.StandardFile = function () {
  function StandardFile(cryptoInstance) {
    _classCallCheck(this, StandardFile);

    // This library runs in native environments as well (react native)
    if (globalScope) {
      // detect IE8 and above, and edge.
      // IE and Edge do not support pbkdf2 in WebCrypto, therefore we need to use CryptoJS
      var IEOrEdge = typeof document !== 'undefined' && document.documentMode || /Edge/.test(navigator.userAgent);

      if (!IEOrEdge && globalScope.crypto && globalScope.crypto.subtle) {
        this.crypto = new SFCryptoWeb();
      } else {
        this.crypto = new SFCryptoJS();
      }
    }

    // This must be placed outside window check, as it's used in native.
    if (cryptoInstance) {
      this.crypto = cryptoInstance;
    }

    this.itemTransformer = new SFItemTransformer(this.crypto);

    this.crypto.SFJS = {
      version: this.version(),
      defaultPasswordGenerationCost: this.defaultPasswordGenerationCost()
    };
  }

  _createClass(StandardFile, [{
    key: "version",
    value: function version() {
      return "003";
    }
  }, {
    key: "supportsPasswordDerivationCost",
    value: function supportsPasswordDerivationCost(cost) {
      // some passwords are created on platforms with stronger pbkdf2 capabilities, like iOS,
      // which CryptoJS can't handle here (WebCrypto can however).
      // if user has high password cost and is using browser that doesn't support WebCrypto,
      // we want to tell them that they can't login with this browser.
      if (cost > 5000) {
        return this.crypto instanceof SFCryptoWeb;
      } else {
        return true;
      }
    }

    // Returns the versions that this library supports technically.

  }, {
    key: "supportedVersions",
    value: function supportedVersions() {
      return ["001", "002", "003"];
    }
  }, {
    key: "isVersionNewerThanLibraryVersion",
    value: function isVersionNewerThanLibraryVersion(version) {
      var libraryVersion = this.version();
      return parseInt(version) > parseInt(libraryVersion);
    }
  }, {
    key: "isProtocolVersionOutdated",
    value: function isProtocolVersionOutdated(version) {
      // YYYY-MM-DD
      var expirationDates = {
        "001": Date.parse("2018-01-01"),
        "002": Date.parse("2020-01-01")
      };

      var date = expirationDates[version];
      if (!date) {
        // No expiration date, is active version
        return false;
      }
      var expired = new Date() > date;
      return expired;
    }
  }, {
    key: "costMinimumForVersion",
    value: function costMinimumForVersion(version) {
      return {
        "001": 3000,
        "002": 3000,
        "003": 110000
      }[version];
    }
  }, {
    key: "defaultPasswordGenerationCost",
    value: function defaultPasswordGenerationCost() {
      return this.costMinimumForVersion(this.version());
    }
  }]);

  return StandardFile;
}();

if (globalScope) {
  // window is for some reason defined in React Native, but throws an exception when you try to set to it
  try {
    globalScope.StandardFile = StandardFile;
    globalScope.SFJS = new StandardFile();
    globalScope.SFCryptoWeb = SFCryptoWeb;
    globalScope.SFCryptoJS = SFCryptoJS;
    globalScope.SFItemTransformer = SFItemTransformer;
    globalScope.SFModelManager = SFModelManager;
    globalScope.SFItem = SFItem;
    globalScope.SFItemParams = SFItemParams;
    globalScope.SFHttpManager = SFHttpManager;
    globalScope.SFStorageManager = SFStorageManager;
    globalScope.SFSyncManager = SFSyncManager;
    globalScope.SFAuthManager = SFAuthManager;
    globalScope.SFMigrationManager = SFMigrationManager;
    globalScope.SFAlertManager = SFAlertManager;
    globalScope.SFPredicate = SFPredicate;
    globalScope.SFHistorySession = SFHistorySession;
    globalScope.SFSessionHistoryManager = SFSessionHistoryManager;
    globalScope.SFItemHistory = SFItemHistory;
    globalScope.SFItemHistoryEntry = SFItemHistoryEntry;
    globalScope.SFPrivilegesManager = SFPrivilegesManager;
    globalScope.SFPrivileges = SFPrivileges;
    globalScope.SFSingletonManager = SFSingletonManager;
  } catch (e) {
    console.log("Exception while exporting window variables", e);
  }
}


}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}]},{},[1])(1)
});
