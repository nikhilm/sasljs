var saslc = require('./lib/binding_sasl');
var sys = require('sys');

process.mixin( exports, saslc );
exports.createSaslConnection = function() {
    var serv = new saslc.ServerConnection();
    serv.mechanisms = serv._mechanisms().split(' ');
    // POP empty element
    serv.mechanisms.pop();
    return serv;
}
