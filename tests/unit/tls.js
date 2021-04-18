var ASSERT = require('assert');
var forge = require('../../lib/forge');
require('../../lib/tls');
require('../../lib/aesCipherSuites');
require('../../lib/util');

(function() {

function createCertificate(cn, data) {
  var keys = forge.pki.rsa.generateKeyPair(512);
  var cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 1);
  var attrs = [{
    name: 'commonName',
    value: cn
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Virginia'
  }, {
    name: 'localityName',
    value: 'Blacksburg'
  }, {
    name: 'organizationName',
    value: 'Test'
  }, {
    shortName: 'OU',
    value: 'Test'
  }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'subjectAltName',
    altNames: [{
      type: 6, // URI
      value: 'https://myuri.com/webid#me'
    }]
  }]);
  cert.sign(keys.privateKey);
  data[cn] = {
    cert: forge.pki.certificateToPem(cert),
    privateKey: forge.pki.privateKeyToPem(keys.privateKey)
  };
}


  describe('tls', function() {
    it('should test TLS 1.0 PRF', function() {
      // Note: This test vector is originally from:
      // http://www.imc.org/ietf-tls/mail-archive/msg01589.html
      // But that link is now dead.
      var secret = forge.util.createBuffer().fillWithByte(0xAB, 48).getBytes();
      var seed = forge.util.createBuffer().fillWithByte(0xCD, 64).getBytes();
      var bytes = forge.tls.prf_tls1(secret, 'PRF Testvector', seed, 104);
      var expect =
        'd3d4d1e349b5d515044666d51de32bab258cb521' +
        'b6b053463e354832fd976754443bcf9a296519bc' +
        '289abcbc1187e4ebd31e602353776c408aafb74c' +
        'bc85eff69255f9788faa184cbb957a9819d84a5d' +
        '7eb006eb459d3ae8de9810454b8b2d8f1afbc655' +
        'a8c9a013';
      ASSERT.equal(bytes.toHex(), expect);
    });

    it('should test sha256 PRF', function() {
      // https://github.com/ctz/pytls/blob/master/tls/prf.py
      var secret = forge.util.createBuffer("\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35");
      var seed = forge.util.createBuffer("\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c");
      var bytes = forge.tls.prf_sha256(secret.bytes(), 'test label', seed.bytes(), 100);
      var expect =
        'e3f229ba727be17b8d122620557cd453c2aab2' +
        '1d07c3d495329b52d4e61edb5a6b301791e90d3' +
        '5c9c9a46b4e14baf9af0fa022f7077def17abfd' +
        '3797c0564bab4fbc91666e9def9b97fce34f796' +
        '789baa48082d122ee42c5a72e5a5110fff70187' +
        '347b66';

      ASSERT.equal(bytes.toHex(), expect);
    });
/*
    it('should test sha384 PRF', function() {
      // https://tools.ietf.org/html/rfc4231
      var secret = "\xcd".repeat(50);
      var label = "\x01\x02\x03\x04\x05\x06\x07\x08";
      var seed = "\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";
      var bytes = forge.tls.prf_sha384(secret, label, seed, 50);
      var expect =
        '3e8a69b7783c25851933ab6290af6ca7' +
        '7a9981480850009cc5577c6e1f573b4e' +
        '6801dd23c4a7d679ccf8a386c674cffb';

      ASSERT.equal(bytes.toHex(), expect);
    });*/

    it('should test sha512 PRF', function() {
      // This test vector is originally from:
      // http://www.ietf.org/mail-archive/web/tls/current/msg03416.html
      var secret = forge.util.createBuffer().putBytes(forge.util.hexToBytes("b0323523c1853599584d88568bbb05eb")).getBytes();
      var seed = forge.util.createBuffer().putBytes(forge.util.hexToBytes("d4640e12e4bcdbfb437f03e6ae418ee5")).getBytes();
      var label = forge.util.createBuffer().putBytes(forge.util.hexToBytes("74657374206c6162656c")).getBytes();
      var bytes = forge.tls.prf_sha512(secret, label,  seed, 196);
      var expect =
        '1261f588c798c5c201ff036e7a9cb5ed' +
        'cd7fe3f94c669a122a4638d7d508b283' +
        '042df6789875c7147e906d868bc75c45' +
        'e20eb40c1cf4a1713b27371f68432592' +
        'f7dc8ea8ef223e12ea8507841311bf68' +
        '653d0cfc4056d811f025c45ddfa6e6fe' +
        'c702f054b409d6f28dd0a3233e498da4' +
        '1a3e75c5630eedbe22fe254e33a1b0e9' +
        'f6b9826675bec7d01a845658dc9c3975' +
        '45401d40b9f46c7a400ee1b8f81ca0a6' +
        '0d1a397a1028bff5d2ef5066126842fb' +
        '8da4197632bdb54ff6633f86bbc836e6' +
        '40d4d898';
      ASSERT.equal(bytes.toHex(), expect);
    });

    function testConnection(done, requestVersion) {
      var end = {};
      var data = {};

      createCertificate('server', data);
      createCertificate('client', data);
      data.client.connection = {};
      data.server.connection = {};

      end.client = forge.tls.createConnection({
        maxVersion: requestVersion,
        server: false,
        caStore: [data.server.cert],
        sessionCache: {},
        cipherSuites: [
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
        virtualHost: 'server',
        verify: function(c, verified, depth, certs) {
          data.client.connection.commonName =
            certs[0].subject.getField('CN').value;
          data.client.connection.certVerified = verified;
          return true;
        },
        connected: function(c) {
          c.prepare('Hello Server');
        },
        getCertificate: function(c, hint) {
          return data.client.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.client.privateKey;
        },
        tlsDataReady: function(c) {
          end.server.process(c.tlsData.getBytes());
        },
        dataReady: function(c) {
          data.client.connection.data = c.data.getBytes();
          c.close();
        },
        closed: function(c) {
          ASSERT.equal(data.client.connection.commonName, 'server');
          ASSERT.equal(data.client.connection.certVerified, true);
          ASSERT.equal(data.client.connection.data, 'Hello Client');
          done();
        },
        error: function(c, error) {
          ASSERT.equal(error.message, undefined);
        }
      });

      end.server = forge.tls.createConnection({
        server: true,
        caStore: [data.client.cert],
        sessionCache: {},
        cipherSuites: [
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA,
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
        connected: function(c) {},
        verifyClient: true,
        verify: function(c, verified, depth, certs) {
          data.server.connection.commonName =
            certs[0].subject.getField('CN').value;
          data.server.connection.certVerified = verified;
          return true;
        },
        getCertificate: function(c, hint) {
          data.server.connection.certHint = hint[0];
          return data.server.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.server.privateKey;
        },
        tlsDataReady: function(c) {
          end.client.process(c.tlsData.getBytes());
        },
        dataReady: function(c) {
          data.server.connection.data = c.data.getBytes();
          data.server.connection.version = c.session.version;
          c.prepare('Hello Client');
          c.close();
        },
        closed: function(c) {
          ASSERT.equal(data.server.connection.certHint, 'server');
          ASSERT.equal(data.server.connection.commonName, 'client');
          ASSERT.equal(data.server.connection.certVerified, true);
          ASSERT.equal(data.server.connection.data, 'Hello Server');
          ASSERT.equal(data.server.connection.version.major, requestVersion.major);
          ASSERT.equal(data.server.connection.version.minor, requestVersion.minor);
        },
        error: function(c, error) {
          ASSERT.equal(error.message, undefined);
        }
      });

      end.client.handshake();
    }

    it('should establish a TLS 1.2 connection and transfer data', done => {testConnection(done, forge.tls.Versions.TLS_1_2)});
    it('should establish a TLS 1.1 connection and transfer data', done => {testConnection(done, forge.tls.Versions.TLS_1_1)});
    it('should establish a TLS 1.0 connection and transfer data', done => {testConnection(done, forge.tls.Versions.TLS_1_0)});

    it('should test cipher suite selection not available', function(done) {
      var end = {};
      var data = {};

      createCertificate('server', data);
      createCertificate('client', data);
      data.client.connection = {connected: false};
      data.server.connection = {connected: false};

      end.client = forge.tls.createConnection({
        server: false,
        caStore: [data.server.cert],
        cipherSuites: [
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA],
        getCertificate: function(c, hint) {
          return data.client.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.client.privateKey;
        },
        connected: function(c) {
            data.client.connection.connected = true;
        },
        tlsDataReady: function(c) {
          end.server.process(c.tlsData.getBytes());
        },
        dataReady: (c)=>{c.close();},
        closed: function(c) {
          ASSERT.equal(data.client.connection.connected, false);
          done();
        },
        error: function(c, error) {
          ASSERT.equal(error.origin, 'server');
          ASSERT.equal(error.alert.level, forge.tls.Alert.Level.fatal);
          ASSERT.equal(error.alert.description, forge.tls.Alert.Description.handshake_failure);
        }
      });

      end.server = forge.tls.createConnection({
        server: true,
        caStore: [data.client.cert],
        sessionCache: {},
        cipherSuites: [
          // intentional mismatch of client server cipher
          forge.tls.CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA],
        connected: function(c) {
            data.server.connection.connected = true;
        },
        getCertificate: function(c, hint) {
          data.server.connection.certHint = hint[0];
          return data.server.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.server.privateKey;
        },
        tlsDataReady: function(c) {
          end.client.process(c.tlsData.getBytes());
        },
        dataReady: (c)=>{c.close();},
        closed: function(c) {
          ASSERT.equal(data.server.connection.connected, false);
        },
        error: function(c, error) {
          ASSERT.equal(error.origin, 'server');
          ASSERT.equal(error.alert.level, forge.tls.Alert.Level.fatal);
          ASSERT.equal(error.alert.description, forge.tls.Alert.Description.handshake_failure);
        }
      });

      end.client.handshake();
      ASSERT.equal(data.client.connection.connected, false);
      ASSERT.equal(data.server.connection.connected, false)
    });

        it('should test minimum version reject connection', function(done) {
      var end = {};
      var data = {};

      createCertificate('server', data);
      createCertificate('client', data);
      data.client.connection = {connected: false};
      data.server.connection = {connected: false};

      end.client = forge.tls.createConnection({
        maxVersion: forge.tls.Versions.TLS_1_1,
        server: false,
        caStore: [data.server.cert],
        getCertificate: function(c, hint) {
          return data.client.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.client.privateKey;
        },
        connected: function(c) {
            data.client.connection.connected = true;
        },
        tlsDataReady: function(c) {
          end.server.process(c.tlsData.getBytes());
        },
        dataReady: (c)=>{c.close();},
        closed: function(c) {
          ASSERT.equal(data.client.connection.connected, false);
          done();
        },
        error: function(c, error) {
          ASSERT.equal(error.origin, 'server');
          ASSERT.equal(error.alert.level, forge.tls.Alert.Level.fatal);
          ASSERT.equal(error.alert.description, forge.tls.Alert.Description.protocol_version);
        }
      });

      end.server = forge.tls.createConnection({
        minVersion: forge.tls.Versions.TLS_1_2,
        server: true,
        caStore: [data.client.cert],
        sessionCache: {},
        connected: function(c) {
            data.server.connection.connected = true;
        },
        getCertificate: function(c, hint) {
          data.server.connection.certHint = hint[0];
          return data.server.cert;
        },
        getPrivateKey: function(c, cert) {
          return data.server.privateKey;
        },
        tlsDataReady: function(c) {
          end.client.process(c.tlsData.getBytes());
        },
        dataReady: (c)=>{c.close();},
        closed: function(c) {
          ASSERT.equal(data.server.connection.connected, false);
        },
        error: function(c, error) {
          ASSERT.equal(error.origin, 'server');
          ASSERT.equal(error.alert.level, forge.tls.Alert.Level.fatal);
          ASSERT.equal(error.alert.description, forge.tls.Alert.Description.protocol_version);
        }
      });

      end.client.handshake();
      ASSERT.equal(data.client.connection.connected, false);
      ASSERT.equal(data.server.connection.connected, false)
    });
  });
})();
